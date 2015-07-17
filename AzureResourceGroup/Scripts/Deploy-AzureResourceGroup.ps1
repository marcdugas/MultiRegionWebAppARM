#Requires -Version 3.0

Param(
  [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
  [string] $ResourceGroupName = 'WebApplication',
  [switch] $UploadArtifacts,
  [string] $StorageAccountName, 
  [string] $StorageContainerName = $ResourceGroupName.ToLowerInvariant() + '-stageartifacts',
  [string] $TemplateFile = '..\Templates\DeploymentTemplate.json',
  [string] $TemplateParametersFile = '..\Templates\DeploymentTemplate.param.dev.json',
  [string] $ArtifactStagingDirectory = '..\bin\Debug\Artifacts',
  [string] $AzCopyPath = '..\Tools\AzCopy.exe'
)

Set-StrictMode -Version 3
Import-Module Azure -ErrorAction SilentlyContinue

try {
    $AzureToolsUserAgentString = New-Object -TypeName System.Net.Http.Headers.ProductInfoHeaderValue -ArgumentList 'VSAzureTools', '1.4'
    [Microsoft.Azure.Common.Authentication.AzureSession]::ClientFactory.UserAgents.Add($AzureToolsUserAgentString)
} catch { }

$OptionalParameters = New-Object -TypeName Hashtable
$TemplateFile = [System.IO.Path]::Combine($PSScriptRoot, $TemplateFile)
$TemplateParametersFile = [System.IO.Path]::Combine($PSScriptRoot, $TemplateParametersFile)

if ($UploadArtifacts)
{
    # Convert relative paths to absolute paths if needed
    $AzCopyPath = [System.IO.Path]::Combine($PSScriptRoot, $AzCopyPath)
    $ArtifactStagingDirectory = [System.IO.Path]::Combine($PSScriptRoot, $ArtifactStagingDirectory)

    Set-Variable ArtifactsLocationName '_artifactsLocation' -Option ReadOnly
    Set-Variable ArtifactsLocationSasTokenName '_artifactsLocationSasToken' -Option ReadOnly

    $OptionalParameters.Add($ArtifactsLocationName, $null)
    $OptionalParameters.Add($ArtifactsLocationSasTokenName, $null)

    # Parse the parameter file and update the values of artifacts location and artifacts location SAS token if they are present
    $JsonContent = Get-Content $TemplateParametersFile -Raw | ConvertFrom-Json
    $JsonParameters = $JsonContent | Get-Member -Type NoteProperty | Where-Object {$_.Name -eq "parameters"}

    if ($JsonParameters -eq $null)
    {
        $JsonParameters = $JsonContent
    }
    else
    {
        $JsonParameters = $JsonContent.parameters
    }

    $JsonParameters | Get-Member -Type NoteProperty | ForEach-Object {
        $ParameterValue = $JsonParameters | Select-Object -ExpandProperty $_.Name

        if ($_.Name -eq $ArtifactsLocationName -or $_.Name -eq $ArtifactsLocationSasTokenName)
        {
            $OptionalParameters[$_.Name] = $ParameterValue.value
        }
    }

    Switch-AzureMode AzureServiceManagement
	$StorageAccountKey = (Get-AzureStorageKey -StorageAccountName $StorageAccountName).Primary
    $StorageAccountContext = New-AzureStorageContext $StorageAccountName (Get-AzureStorageKey $StorageAccountName).Primary

    # Generate the value for artifacts location if it is not provided in the parameter file
    $ArtifactsLocation = $OptionalParameters[$ArtifactsLocationName]
    if ($ArtifactsLocation -eq $null)
    {
        $ArtifactsLocation = $StorageAccountContext.BlobEndPoint + $StorageContainerName
        $OptionalParameters[$ArtifactsLocationName] = $ArtifactsLocation
    }
   
    # Use AzCopy to copy files from the local storage drop path to the storage account container
    & "$AzCopyPath" """$ArtifactStagingDirectory"" $ArtifactsLocation /DestKey:$StorageAccountKey /S /Y /Z:""$env:LocalAppData\Microsoft\Azure\AzCopy\$ResourceGroupName"""
	
    # Generate the value for artifacts location SAS token if it is not provided in the parameter file
    $ArtifactsLocationSasToken = $OptionalParameters[$ArtifactsLocationSasTokenName]

    if ($ArtifactsLocationSasToken -eq $null)
    {
       # Create a SAS token for the storage container - this gives temporary read-only access to the container (defaults to 1 hour).
       $ArtifactsLocationSasToken = New-AzureStorageContainerSASToken -Container $StorageContainerName -Context $StorageAccountContext -Permission r
       $ArtifactsLocationSasToken = ConvertTo-SecureString $ArtifactsLocationSasToken -AsPlainText -Force
       $OptionalParameters[$ArtifactsLocationSasTokenName] = $ArtifactsLocationSasToken
    }
}

# Create or update the resource group using the specified template file and template parameters file
Switch-AzureMode AzureResourceManager
New-AzureResourceGroup -Name $ResourceGroupName `
                       -Location $ResourceGroupLocation `
                       -TemplateFile $TemplateFile `
                       -TemplateParameterFile $TemplateParametersFile `
                        @OptionalParameters `
                        -Force -Verbose


Write-Host "Resource Group Deployed..."
# Switch to Mangement Mode to use the stable Traffic Manager Cmdlets
# https://azure.microsoft.com/en-gb/documentation/articles/traffic-manager-powershell-arm/ (In Preview)
# Known Issue: Having PowerShell Tools for Visual Studio (2013) causes "There is a problem in the PowerShell host service."
Switch-AzureMode -Name AzureServiceManagement

#NOTE: PowerShell Tools for Visual Studio caused it to crash on my machine
#NOTE: Ensure you enable PowerShell security to "run" on local machine
#Possible Enhancement is to use copyIndex() to copy resources

#Only proceed if the following parameters are provided: Region1WebSiteName, Region2WebSiteName, TrafficManagerProfileName, TrafficManagerProfileDomainName
if($JsonContent -ne $null -and $JsonContent.parameters.TrafficManagerProfileName -ne $null -and $JsonContent.parameters.TrafficManagerLoadBalancingMethod -ne $null -and $JsonContent.parameters.TrafficManagerProfileDomainName -ne $null  -and $JsonContent.parameters.Region1WebSiteName -ne $null -and  $JsonContent.parameters.Region2WebSiteName -ne $null){
	$region1WebSiteDomain = $JsonContent.parameters.Region1WebSiteName.value + ".azurewebsites.net"
	$region2WebSiteDomain = $JsonContent.parameters.Region2WebSiteName.value + ".azurewebsites.net"
	$trafficManagerProfileName = $JsonContent.parameters.TrafficManagerProfileName.value
	$trafficManagerProfileDomainName = $JsonContent.parameters.TrafficManagerProfileDomainName.value
	$trafficManagerLoadBalancingMethod = $JsonContent.parameters.TrafficManagerLoadBalancingMethod.value

	$websiteDomains = $region1WebSiteDomain, $region2WebSiteDomain

	Write-Host "Getting Traffic Manager for Profile $($trafficManagerProfileName) ..."
	$tmprofile = Get-AzureTrafficManagerProfile -Name $trafficManagerProfileName -ErrorAction Ignore

	if($tmprofile -eq $null){
		Write-Host "Traffic Manager Does Not exist, creating  $($trafficManagerProfileName) ..."
		# TODO: additional settings can be parameterized
		$tmprofile  = New-AzureTrafficManagerProfile -Name $trafficManagerProfileName -DomainName $trafficManagerProfileDomainName -LoadBalancingMethod $trafficManagerLoadBalancingMethod -Ttl 30 -MonitorProtocol Http -MonitorPort 80 -MonitorRelativePath / 
		Write-Host "Traffic Manager Profile  $($trafficManagerProfileName) created."
	}else{
		# Update settings 
		$tmprofile.LoadBalancingMethod = $trafficManagerLoadBalancingMethod
	}

	Write-Host $tmprofile.LoadBalancingMethod

	# Create Endpoints for provided WebSiteNames
	#TODO: Make sure Tier of App Hosting Plan is Standard and in seperate regions
	ForEach($domain in $websiteDomains)
	{
		Write-Host "Finding Endpoint with domain $($domain) ..."
		
		$endpoint = $null
		if($tmprofile.Endpoints -ne $null){
			$endpoint = $tmprofile.Endpoints | Where-Object { $_.DomainName -eq $domain}
		}

		if($endpoint -eq $null){
			Write-Host "Adding Traffic Manager Endpoint $($domain) ..."
			$tmprofile = Add-AzureTrafficManagerEndpoint -TrafficManagerProfile $tmprofile -DomainName $domain -Status "Enabled" -Type "AzureWebsite"
			Write-Host "Added Traffic Manager Endpoint $($domain)."
		}else{
			Write-Host "Endpoint $($domain) already exists."
		}
	}
	
	Write-Host "Saving Traffic Manager Profile..."
	Set-AzureTrafficManagerProfile –TrafficManagerProfile $tmprofile
	Write-Host "Saved Traffic Manager Profile."
}

#TODO: Get all WebSite Resources from Resource Group
#TODO: Map all of them to the Azure Traffic Manager