function Request-AccessToken {
	[CmdletBinding()]
	[OutputType('string')]
	param
	(
		[Parameter()]
		[Parameter(ParameterSetName = 'Refresh')]
		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[string]$ClientId,

		[Parameter()]
		[Parameter(ParameterSetName = 'Refresh')]
		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[string]$ClientSecret,

		[Parameter(Mandatory, ParameterSetName = 'Refresh')]
		[ValidateNotNullOrEmpty()]
		[string]$RefreshToken,
		
		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[string[]]$Scope = @('drive'),

		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('online', 'offline')]
		[string]$AccessType = 'offline',

		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateSet('code', 'token')]
		[string]$ResponseType = 'code',
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Parameter(ParameterSetName = 'Refresh')]
		[Parameter(ParameterSetName = 'NewToken')]
		[string]$ApplicationName = 'PSGoogleDocs'
	)
	
	$ErrorActionPreference = 'Stop'
	try {

		if (-not $PSBoundParameters.ContainsKey('ClientId')) {
			$ClientId = (Get-PSGoogleDocsApiAuthInfo).ClientId
		}
		if (-not $PSBoundParameters.ContainsKey('ClientSecret')) {
			$ClientSecret = (Get-PSGoogleDocsApiAuthInfo).ClientSecret
		}

		$payload = @{
			client_id    = [System.Uri]::EscapeUriString($ClientId)
			redirect_uri = [System.Uri]::EscapeUriString("urn:ietf:wg:oauth:2.0:oob")
		}

		if ($PSCmdlet.ParameterSetName -eq 'NewToken') {
			$endpointCodeUri = 'https://accounts.google.com/o/oauth2/auth'
		
			$scopes = @()
			foreach ($s in $Scope) {
				$scopes += "https://www.googleapis.com/auth/$s" 
			}
			$payload += @{
				'scope'                  = [System.Uri]::EscapeUriString($scopes -join ',')
				'access_type'            = $AccessType
				'include_granted_scopes' = 'true'
				'response_type'          = 'code'
				'state'                  = 'ps_state'
			}

			$keyValues = @()
			$payload.GetEnumerator() | sort Name | foreach {
				$keyValues += "$($_.Key)=$($_.Value)"
			}
		
			$keyValueString = $keyValues -join '&'
			$authUri = '{0}?{1}' -f $endpointCodeUri, $keyValueString
		
			& start $authUri
		
			$code = Read-Host -Prompt 'Please enter the authorization code displayed in your web browser'

			$payload += @{
				code          = [System.Uri]::EscapeUriString($code)
				grant_type    = 'authorization_code'
				client_secret = [System.Uri]::EscapeUriString($ClientSecret)
			}
		} elseif ($PSCmdlet.ParameterSetName -eq 'Refresh') {
			$payload += @{
				'refresh_token' = $RefreshToken
				'grant_type'    = 'refresh_token'
				client_secret   = [System.Uri]::EscapeUriString($ClientSecret)
			}
		}

		$endpointTokenUri = 'https://www.googleapis.com/oauth2/v3/token'
		$response = Invoke-WebRequest -Uri $endpointTokenUri -Method POST -Body $payload

		ConvertFrom-Json -InputObject $response.Content | Select-Object -Property access_token, refresh_token
		
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Get-PSGoogleDocsApiAuthInfo {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$RegistryKeyPath = 'HKCU:\Software\PSGoogleDocs'
	)
	
	$ErrorActionPreference = 'Stop'

	function decrypt([string]$TextToDecrypt) {
		$secure = ConvertTo-SecureString $TextToDecrypt
		$hook = New-Object system.Management.Automation.PSCredential("test", $secure)
		$plain = $hook.GetNetworkCredential().Password
		return $plain
	}

	try {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			Write-Warning 'No PSGoogleDocs API info found in registry'
		} else {
			$keys = (Get-Item -Path $RegistryKeyPath).Property
			$ht = @{}
			foreach ($key in $keys) {
				$ht[$key] = decrypt (Get-ItemProperty -Path $RegistryKeyPath).$key
			}
			[pscustomobject]$ht
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Save-PSGoogleDocsApiAuthInfo {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$ClientId,

		[Parameter()]
		[string]$ClientSecret,

		[Parameter(ValueFromPipelineByPropertyName)]
		[Alias('access_token')]
		[string]$AccessToken,
	
		[Parameter(ValueFromPipelineByPropertyName)]
		[Alias('refresh_token')]
		[string]$RefreshToken,

		[Parameter()]
		[string]$APIKey,
	
		[Parameter()]
		[string]$RegistryKeyPath = "HKCU:\Software\PSGoogleDocs"
	)

	begin {
		function encrypt([string]$TextToEncrypt) {
			$secure = ConvertTo-SecureString $TextToEncrypt -AsPlainText -Force
			$encrypted = $secure | ConvertFrom-SecureString
			return $encrypted
		}
	}
	
	process {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			New-Item -Path ($RegistryKeyPath | Split-Path -Parent) -Name ($RegistryKeyPath | Split-Path -Leaf) | Out-Null
		}
		
		$values = $PSBoundParameters.GetEnumerator().where({ $_.Key -ne 'RegistryKeyPath' -and $_.Value}) | Select-Object -ExpandProperty Key
		
		foreach ($val in $values) {
			Write-Verbose "Creating $RegistryKeyPath\$val"
			New-ItemProperty $RegistryKeyPath -Name $val -Value $(encrypt $((Get-Variable $val).Value)) -Force | Out-Null
		}
	}
}

function Invoke-GDriveApiCall {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ApiCategory = 'files',

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Payload,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Parameters,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$PageToken,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$HTTPMethod = 'GET',

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Uri
	)

	$ErrorActionPreference = 'Stop'

	if (-not $PSBoundParameters.ContainsKey('Uri')) {
		$Uri = 'https://www.googleapis.com/drive/v3/{0}' -f $ApiCategory	
	}

	$invRestParams = @{
		Method      = $HTTPMethod
		ErrorAction = 'Stop'
	}
	$apiPayload = @{}

	$invRestParams.Headers = @{ 
		'Authorization' = "Bearer $((Get-PSGoogleDocsApiAuthInfo).AccessToken)" 
	}

	if ($HTTPMethod -ne 'GET') {
		$invRestParams.Headers += @{ 
			'Content-Type' = 'application/json'
		}
	}
	$body = $Payload + $apiPayload

	if ($PageToken) {
		$body['pageToken'] = $PageToken
	}
	
	if ($HTTPMethod -ne 'GET') {
		$body = $body | ConvertTo-Json -Depth 5
	}

	if ($HTTPMethod -ne 'DELETE') {
		$invRestParams.Body = $body
	}
	$invRestParams.Uri = $uri

	try {
		$result = Invoke-RestMethod @invRestParams
	} catch {
		if ($_.Exception.Message -like '*(401) Unauthorized*') {
			## The token may be expired. Grab another one using the refresh token and try again
			$apiCred = Get-PSGoogleDocsApiAuthInfo
			$tokens = Request-AccessToken -ClientId $apiCred.ClientId -ClientSecret $apiCred.ClientSecret -RefreshToken $apiCred.RefreshToken
			$tokens | Save-PSGoogleDocsApiAuthInfo
			$invParams = @{
				Payload     = $Payload
				HTTPMethod  = $HTTPMethod
				ApiCategory = $ApiCategory
			}
			if ($PageToken) {
				$invParams.PageToken = $PageToken
			}
			Invoke-GDriveApiCall @invParams
		} else {
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}

	if ($result.files) {
		$result.files
	} else {
		$result
	}

	if ($result.PSObject.Properties.Name -contains 'nextPageToken') {
		Invoke-GDriveApiCall -PageToken $result.nextPageToken -Payload $Payload -ApiMethod $ApiMethod -ApiName $ApiName
	}
}

function Get-File {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)

	$ErrorActionPreference = 'Stop'

	$invParams = @{
		ApiCategory = 'files'
	}
	if ($PSBoundParameters.ContainsKey('Name')) {
		$invParams.Payload = @{ 'q' = "name='$Name'"}
	}
	Invoke-GDriveApiCall @invParams
}

# function Export-File {
# 	[OutputType('pscustomobject')]
# 	[CmdletBinding()]
# 	param
# 	(
# 		[Parameter(Mandatory, ValueFromPipeline)]
# 		[ValidateNotNullOrEmpty()]
# 		[pscustomobject]$File,

# 		[Parameter()]
# 		[ValidateNotNullOrEmpty()]
# 		[ValidateSet('text/plain', 'text/html', 'application/zip', 'application/rtf', 'application/vnd.oasis.opendocument.text', 'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/epub+zip')]
# 		[string]$MimeType
# 	)

# 	$ErrorActionPreference = 'Stop'
	
# 	$uri = "https://www.googleapis.com/drive/v3/files/{0}/export?mimeType={1}" -f $File.id, [uri]::EscapeDataString($MimeType)
# 	Invoke-GDriveApiCall -Uri $uri
# }


function Export-File {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[pscustomobject]$File,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('HTML', 'HTMLZipped', 'PlainText', 'RichText', 'OpenOfficeDoc', 'MSWordDoc', 'EPUB')]
		[string]$FileType
	)

	$ErrorActionPreference = 'Stop'

	$typetoMimeMap = @{
		HTML          = 'text/html'
		HTMLZipped    = 'application/zip'
		PlainText     = 'text/plain'
		RichText      = 'application/rtf'
		OpenOfficeDoc = 'application/vnd.oasis.opendocument.text'
		MSWordDoc     = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
		EPUB          = 'application/epub+zip'
	}
	$mimeType = $typetoMimeMap[$FileType]

	$uri = "https://www.googleapis.com/drive/v3/files/{0}/export?mimeType={1}" -f $File.id, [uri]::EscapeDataString($mimeType)
	Invoke-GDriveApiCall -Uri $uri
}