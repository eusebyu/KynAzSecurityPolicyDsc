$script:DSCResourceName = 'MSFT_AzUserRightsAssignment'

$resourcePath = (Get-DscResource -Name $script:DSCResourceName).Path
Import-Module $resourcePath -Force

# S-1-5-6 = NT Authority\Service
# S-1-5-90-0 = 'window manager\window manager group'

$rule = @{
    Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
    Identity = 'builtin\Administrators','*S-1-5-6','S-1-5-90-0'
}

$deviationRule = @{
    Policy   = 'Change_the_system_time'
    Identity = 'builtin\Administrators','*S-1-5-6','S-1-5-90-0'
    Url      = "$PSScriptRoot\deviations.json"
}

$removeAll = @{
    Policy   = 'Act_as_part_of_the_operating_system'
    Identity = ""
}

$removeGuests = @{
    Policy = 'Deny_log_on_locally'
    Identity = 'Guests'
}

# Add an identities so we can verify it gets removed
Set-TargetResource -Policy $removeAll.Policy -Identity 'Administrators' -Ensure 'Present'
Set-TargetResource -Policy $removeGuests.Policy -Identity 'Guests' -Ensure 'Present'

configuration MSFT_AzUserRightsAssignment_config {
    Import-DscResource -ModuleName SecurityPolicyDsc

    AzUserRightsAssignment AccessCredentialManagerAsaTrustedCaller
    {
        Policy   = $rule.Policy
        Identity = $rule.Identity
    }

    AzUserRightsAssignment ChangeTheSystemTime
    {
        Policy       = $deviationRule.Policy
        Identity     = $deviationRule.Identity
        DeviationUrl = $deviationRule.Url
    }

    AzUserRightsAssignment RemoveAllActAsOS
    {
        Policy   = $removeAll.Policy
        Identity = $removeAll.Identity
    }

    AzUserRightsAssignment DenyLogOnLocally
    {
        Policy   = $removeGuests.Policy
        Identity = $removeGuests.Identity
        Ensure   = 'Absent'
    }
}
