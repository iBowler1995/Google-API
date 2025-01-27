Function Get-GoogleAccessToken{

     <#
		IMPORTANT:
        ===========================================================================
        This script is provided 'as is' without any warranty. Any issues stemming 
        from use is on the user.
        ===========================================================================
		.DESCRIPTION
		Retrieves and returns an access token for Google Calendar API. (Can be edited to change scope)
		===========================================================================
		.PARAMETER CredentialsFile
		Credentials JSON file for your service account downloaded from Google Cloud Console
		===========================================================================
		.EXAMPLE
		Get-GoogleAccessToken -Credentials File C:\Temp\Creds.json <--- Gets you your token
	#>
    
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $True)]
        [String]$CredentialsFile

    )

    #Loading the credentials file
    Try{
        $ServiceAccountCredentials = Get-Content -Raw -Path $CredentialsFile | ConvertFrom-Json
    }
    Catch {
        Write-Host "Error at line $($_.InvocationInfo.ScriptLineNumber) while loading credentials file: $($_.Exception.Message)"
    }

    #Declaring variables
    $ClientEmail = $ServiceAccountCredentials.client_email
    $PrivateKey = $ServiceAccountCredentials.private_key
    $TokenUri = $ServiceAccountCredentials.token_uri
    $Scope = "https://www.googleapis.com/auth/calendar"

    Try{
        #Formatting the private key
        $PrivateKeyFormatted = $PrivateKey -replace "-----BEGIN PRIVATE KEY-----", ""
        $PrivateKeyFormatted = $PrivateKeyFormatted -replace "-----END PRIVATE KEY-----", ""
        $PrivateKeyFormatted = $PrivateKeyFormatted -replace "\s+", ""  #Removes line breaks and whitespace (this was new to me, so I added this comment)
        $PrivateKeyBytes = [Convert]::FromBase64String($PrivateKeyFormatted)
    }
    Catch {
        Write-Host "Error at line $($_.InvocationInfo.ScriptLineNumber) while formatting the priave key: $($_.Exception.Message)"
    }

    #Creating the JSON Web Token header (I can't lie, I had to steal these next few bits from Stack Exchange. This was a new token format for me)
    $Header = @{
        alg = "RS256"
        typ = "JWT"
    }
    $HeaderJson = $Header | ConvertTo-Json -Depth 10 -Compress
    $HeaderBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($HeaderJson))

    #Creating the JWT claims 
    $Now = [int][double]::Parse((Get-Date -UFormat %s))
    $Expiration = $Now + 3600  # Token valid for 1 hour
    $ClaimSet = @{
        iss = $ClientEmail
        scope = $Scope
        aud = $TokenUri
        exp = $Expiration
        iat = $Now
    }
    $ClaimSetJson = $ClaimSet | ConvertTo-Json -Depth 10 -Compress
    $ClaimSetBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ClaimSetJson))

    Try{
        #Signing the JWT with the private key
        $DataToSign = "$HeaderBase64.$ClaimSetBase64"
        $CryptoServiceProvider = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $CryptoServiceProvider.ImportPkcs8PrivateKey($PrivateKeyBytes, [ref]0)
    }
    Catch {
        Write-Host "Error at line $($_.InvocationInfo.ScriptLineNumber) while signing token: $($_.Exception.Message)"
    }

    $SignatureBytes = $CryptoServiceProvider.SignData(
        [System.Text.Encoding]::UTF8.GetBytes($DataToSign),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $SignatureBase64 = [Convert]::ToBase64String($SignatureBytes)

    #Constructing the token
    $Jwt = "$DataToSign.$SignatureBase64"

    Try{
        #Finally, we request the token and pray we got it right
        $TokenResponse = Invoke-RestMethod -Uri $TokenUri -Method Post -Body @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            assertion = $Jwt
        } -ContentType "application/x-www-form-urlencoded"

        $AccessToken = $TokenResponse.access_token

        Return $AccessToken
    }
    Catch {
        Write-Host "Error at line $($_.InvocationInfo.ScriptLineNumber) while submitting token request: $($_.Exception.Message)"
    }

}