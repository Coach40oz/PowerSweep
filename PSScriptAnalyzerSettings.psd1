@{
    Severity = @('Error', 'Warning')

    IncludeDefaultRules = $true

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @('5.1', '7.0')
        }

        PSAvoidUsingWriteHost = @{
            Enable = $false
        }

        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $false
        }

        PSUseApprovedVerbs = @{
            Enable = $false
        }

        PSAvoidUsingPositionalParameters = @{
            Enable = $false
        }
    }

    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseApprovedVerbs',
        'PSAvoidUsingPositionalParameters'
    )
}
