#################
# AzureDevOpsAPI.ps1
#
# References:
#     https://docs.microsoft.com/en-us/rest/api/azure/devops/?view=azure-devops-rest-5.1
#     https://www.imaginet.com/2019/how-use-azure-devops-rest-api-with-powershell/
#     https://mcpmag.com/articles/2019/04/02/parse-a-rest-api-with-powershell.aspx
#     https://jessehouwing.net/azure-devops-git-setting-default-repository-permissions/
#     https://stackoverflow.com/questions/40495248/create-hashtable-from-json
#     https://github.com/DarqueWarrior/vsteam
#     https://stackoverflow.com/questions/56849137/need-rest-api-to-get-the-permission-details-from-azure-devops-using-powershell
#     https://developercommunity.visualstudio.com/idea/365828/set-version-control-permissions-by-rest-api.html
#     https://blog.devopsabcs.com/index.php/2019/06/24/one-project-to-rule-them-all-3/
#     https://stackoverflow.com/questions/46411920/get-a-list-of-who-has-what-access-to-git-repositories
#     https://stackoverflow.com/questions/2648052/using-powershells-bitwise-operators
#     https://dev.to/omiossec/getting-started-with-azure-devops-api-with-powershell-59nn
#################

#################
# PARAMETERS
#################
$Method = "ProjectGroupMembers" #Projects, ProjectGroupMembers, ProjectTeamMembers, ProjectTFVCItems, ProjectRepositories, ACLACEs, ProjectDeploymentApprovers
$LogFileBasePath = "Path\Where\Output\File\Written"
$LogFileDateSuffix = "20210113"
$OrganizationName = "YourOrgName"
$ProjectName = "YourProjectName" #Team project name for which to produce report
$PersonalAccessTokenName = "Audit_Read" #PAT must have code read permission at minimum
$PersonalAccessToken = "PersonalAccessToken"

#################
# FUNCTIONS
#################
function LogInitalize([string]$LogFile) {
    #Empty log file if exists, else create
    If (Test-Path -Path $LogFile) {
        Clear-Content -Path $LogFile
    }
    Else {
        New-Item -Type file -Path $LogFile
    }
}

function LogWrite([string]$LogFile, [string]$LogString) {
    Add-Content $LogFile -value $LogString
}

function HostWrite([string]$HostString) {
    Write-Host $HostString
}

function Create-BasicAuthHeader {
    Param(
#        [Parameter(Mandatory=$True)]
#        [string]$Name,
        [Parameter(Mandatory=$True)]
        [string]$PAT
    )
  
    $Header = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($PAT)")) }

#    $Auth = "{0}:{1}" -f $Name, $PAT
#    $Auth = [System.Text.Encoding]::UTF8.GetBytes($Auth)
#    $Auth = [System.Convert]::ToBase64String($Auth)
#    $Header = @{Authorization=("Basic {0}" -f $Auth)} 
    $Header
}

function GetRestResult {
    Param(
        [string]$RestUri
    )
    
#    Invoke-RestMethod -Uri $RestUri -Headers (Create-BasicAuthHeader $PersonalAccessTokenName $PersonalAccessToken) -Method Get
    Invoke-RestMethod -Uri $RestUri -Headers (Create-BasicAuthHeader $PersonalAccessToken) -Method Get
}

function GetRestResultRaw {
    Param(
        [string]$RestUri
    )
    
#    Invoke-WebRequest -Uri $RestUri -Headers (Create-BasicAuthHeader $PersonalAccessTokenName $PersonalAccessToken) -Method Get
    Invoke-WebRequest -Uri $RestUri -Headers (Create-BasicAuthHeader $PersonalAccessToken) -Method Get
}

function GetGroup {
    Param(
        [string]$Descriptor
    )
    $GroupURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/groups/$Descriptor"
    
    GetRestResult $GroupURL
}

function GetGroups {
    Param(
        [string]$ScopeDescriptor,
        [string]$SubjectTypes
    )

    $GroupsURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/groups?scopeDescriptor=$ScopeDescriptor&subjectTypes=$SubjectTypes"
    
    (GetRestResult $GroupsURL).value
}

function GetGroupPrincipalName {
    Param(
        [string]$Descriptor
    )
    $Group = GetGroup $Descriptor
    $GroupOriginId = $Group.originId
    $GroupPrincipalName = $Group.principalName
    Write-Host "$Indent`tGroup`t$GroupOriginId`t$GroupPrincipalName"
    LogWrite $LogFile "$Indent`tGroup`t$GroupOriginId`t$GroupPrincipalName"

    $GroupPrincipalName
}

function GetGroupMember {
    Param(
        [string]$Descriptor,
        [string]$GroupName,
        [string]$Indent
    )
    $GroupMemberURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/users/$Descriptor"
    $GroupMember = GetRestResult $GroupMemberURL
    $GroupMemberOriginId = $GroupMember.originId
    $GroupMemberDisplayName = $GroupMember.displayName
    $GroupMemberPrincipalName = $GroupMember.principalName
    $GroupMemberDescriptor = $GroupMember.descriptor
    $GroupMemberType = $GroupMemberDescriptor.Split(".")[0]
    Write-Host "`t`t$Indent$GroupName`t$GroupMemberOriginId`t$GroupMemberDisplayName`t$GroupMemberPrincipalName`t$GroupMemberDescriptor`t$GroupMemberType"
    LogWrite $LogFile "`t`t$Indent$GroupName`t$GroupMemberOriginId`t$GroupMemberDisplayName`t$GroupMemberPrincipalName`t$GroupMemberDescriptor`t$GroupMemberType"
}

function GetGroupMembers {
    Param (
        [string]$Descriptor,
        [string]$GroupName,
        [string]$Indent
    )
    $GroupPrincipalName = GetGroupPrincipalName $Descriptor $Indent
    $GroupMembersURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/memberships/$Descriptor" + "?direction=down"
    $GroupMembers = (GetRestResult $GroupMembersURL).value
    ForEach ($GroupMember In $GroupMembers) {
        $GroupMemberDescriptor = $GroupMember.memberDescriptor
        $GroupMemberType = $GroupMemberDescriptor.Split(".")[0]
        If ($GroupMemberType -eq "aadgp" -or $GroupMemberType -eq "vssgp") {
            $Indent = "`t$Indent"
            GetGroupMembers $GroupMemberDescriptor $GroupName $Indent
        }
        Else {
            If ($GroupName = $GroupPrincipalName) {
                $GroupName = "User"
            }
            GetGroupMember $GroupMemberDescriptor $GroupName $Indent
        }
    }
}

function GetProjects {
    Param (
        [string]$OrganizationName
    )
    $ProjectsURL = "https://dev.azure.com/$OrganizationName/_apis/projects"

    $Projects = (GetRestResult $ProjectsURL).value
    ForEach ($Project In $Projects) {
        $ProjectID = $Project.Id
        $ProjectName = $Project.name

        Write-Host "$ProjectID`t$ProjectName"
    }
}

function GetProject {
    Param(
        [string]$ProjectName
    )

    $ProjectsURL = "https://dev.azure.com/$OrganizationName/_apis/projects/$ProjectName"
    
    GetRestResult $ProjectsURL
}

function GetProjectId {
    Param(
        [string]$ProjectName
    )
    $Project = GetProject $ProjectName
    $ProjectId = $Project.id

    $ProjectId
}

function GetProjectScopeDescriptor {
    Param(
        [string]$ProjectName
    )
    $ProjectId = GetProjectId $ProjectName
    $ScopeDescriptorURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/descriptors/$ProjectId"
    $Scope = GetRestResult $ScopeDescriptorURL

    $Scope.value
}

function GetProjectTeams {
    Param(
        [string]$ProjectName
    )

    $ProjectId = GetProjectId $ProjectName
    $ProjectTeamsURL = "https://dev.azure.com/$OrganizationName/_apis/projects/$ProjectId/teams"
    
    (GetRestResult $ProjectTeamsURL).value
}

function GetProjectTeamMember {
    Param(
        [string]$Descriptor,
        [string]$GroupName,
        [string]$Indent
    )
    $GroupMemberURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/users/$Descriptor"
    $GroupMember = GetRestResult $GroupMemberURL
    $GroupMemberOriginId = $GroupMember.originId
    $GroupMemberDisplayName = $GroupMember.displayName
    $GroupMemberPrincipalName = $GroupMember.principalName
    $GroupMemberDescriptor = $GroupMember.descriptor
    $GroupMemberType = $GroupMemberDescriptor.Split(".")[0]
    Write-Host "$Indent`tUser`t$GroupMemberDisplayName`t$GroupMemberPrincipalName`t$GroupMemberDescriptor`t$GroupMemberType"
    LogWrite $LogFile "$Indent`tUser`t$GroupMemberDisplayName`t$GroupMemberPrincipalName`t$GroupMemberDescriptor`t$GroupMemberType"
}

function GetProjectTFVCItems {
    Param(
        [string]$OrganizationName,
        [string]$ProjectName
    )
    $ProjectId = GetProjectId $ProjectName
    Write-Host "Project`t$ProjectId`t$ProjectName"
    LogWrite $LogFile "Project`t$ProjectId`t$ProjectName"
    $ProjectTFVCItemsURL = "https://dev.azure.com/$OrganizationName/$ProjectName/_apis/tfvc/items"
    $ProjectTFVCItems = (GetRestResult $ProjectTFVCItemsURL).value
    ForEach ($ProjectTFVCItem In $ProjectTFVCItems) {
        $ProjectTFVCItemPath = $ProjectTFVCItem.path
        $ProjectTFVCItemIsBranch = $ProjectTFVCItem.isBranch
        $ProjectTFVCItemIsFolder = $ProjectTFVCItem.isFolder
        
        If ($ProjectTFVCItemIsBranch -eq $Null) {
            $ProjectTFVCItemIsBranch = $False
        }
        If ($ProjectTFVCItemIsFolder -eq $Null) {
            $ProjectTFVCItemIsFolder = $False
        }
        If ($ProjectTFVCItemIsBranch -eq $True -and $ProjectTFVCItemIsFolder -eq $True) {
            $ProjectTFVCItemType = "Branch"
        }
        ElseIf ($ProjectTFVCItemIsBranch -eq $True -and $ProjectTFVCItemIsFolder -eq $False) {
            $ProjectTFVCItemType = "Unknown"
        }
        ElseIf ($ProjectTFVCItemIsBranch -eq $False -and $ProjectTFVCItemIsFolder -eq $True) {
            If ($projectTFVCItemPath -eq "$/$ProjectName") {
                $ProjectTFVCItemType = "Root" 
            }
            Else {
                $ProjectTFVCItemType = "Folder" 
            }
        }
        Else {
            $ProjectTFVCItemType = "File" 
        }
        If ($ProjectTFVCItemType -ne "Root") {
            $Indent = "`t`t"
        }
        Else {
            $Indent = "`t"
        }
        Write-Host "$Indent$ProjectTFVCItemType`t$ProjectTFVCItemPath"
        LogWrite $LogFile "$Indent$ProjectTFVCItemType`t$ProjectTFVCItemPath"
    }
}

function GetProjectRepositories {
    Param(
        [string]$OrganizationName,
        [string]$ProjectName
    )
    $ProjectId = GetProjectId $ProjectName
    Write-Host "Project`t$ProjectId`t$ProjectName"
    LogWrite $LogFile "Project`t$ProjectId`t$ProjectName"
    $ProjectRepositoriesURL = "https://dev.azure.com/$OrganizationName/$ProjectName/_apis/git/repositories"
    $ProjectRepositories = (GetRestResult $ProjectRepositoriesURL).value
    ForEach ($ProjectRepository In $ProjectRepositories) {
        $ProjectRepositoryId = $ProjectRepository.id
        $ProjectRepositoryName = $ProjectRepository.name
        Write-Host "`tRepository`t$ProjectRepositoryId`t$ProjectRepositoryName"
        LogWrite $LogFile "`tRepository`t$ProjectRepositoryId`t$ProjectRepositoryName"
    }
}

function GetProjectGroupMembers {
    Param(
        [string]$OrganizationName,
        [string]$ProjectName
    )
    $ProjectId = GetProjectId $ProjectName
    Write-Host "Project`t$ProjectId`t$ProjectName"
    LogWrite $LogFile "Project`t$ProjectId`t$ProjectName"
    $ProjectScopeDescriptor = GetProjectScopeDescriptor $ProjectName
    $Groups = GetGroups $ProjectScopeDescriptor "vssgp"
    $Indent = ""
    ForEach ($Group In $Groups) {
        $GroupPrincipalName = $Group.principalName
        $GroupProjectName = $GroupPrincipalName.Split("\")[0]
        $GroupDescriptor = $Group.descriptor
        $GroupType = $GroupDescriptor.Split(".")[0]
        $GroupDisplayName = $Group.displayName
        GetGroupMembers $GroupDescriptor $GroupPrincipalName $Indent
    }
}

function GetProjectTeamMembers {
    Param(
        [string]$OrganizationName,
        [string]$ProjectName
    )
    $ProjectId = GetProjectId $ProjectName
    $ProjectTeams = GetProjectTeams $ProjectName
    Write-Host "Project`t$ProjectId`t$ProjectName"
    LogWrite $LogFile "Project`t$ProjectId`t$ProjectName"
    ForEach ($ProjectTeam In $ProjectTeams) {
        $ProjectTeamId = $ProjectTeam.id
        $ProjectTeamName = $ProjectTeam.name
        Write-Host "`tProjectTeam`t$ProjectTeamId`t$ProjectTeamName"
        LogWrite $LogFile "`tProjectProjectTeam`t$ProjectTeamId`t$ProjectTeamName"
        $ProjectTeamMembersURL = "https://dev.azure.com/$OrganizationName/_apis/projects/$ProjectId/teams/$ProjectTeamId/members"
        $ProjectTeamMembers = (GetRestResult $ProjectTeamMembersURL).value
        ForEach ($ProjectTeamMember In $ProjectTeamMembers) {
            $ProjectTeamMemberDescriptor = $ProjectTeamMember.identity.descriptor
            $ProjectTeamMemberType = $ProjectTeamMemberDescriptor.Split(".")[0]
            $ProjectTeamMemberDisplayName = $ProjectTeamMember.identity.displayName
            $Indent = "`t"
            If ($ProjectTeamMemberType -eq "aadgp" -or $ProjectTeamMemberType -eq "vssgp") {
                GetGroupMembers $ProjectTeamMemberDescriptor $ProjectTeamMemberDisplayName $Indent
            }
            Else {
                GetProjectTeamMember $ProjectTeamMemberDescriptor $ProjectTeamMemberDisplayName $Indent
            }
        }
    }
}

function GetIdentityDescriptor {
    Param(
        [string]$OrganizationName,
        [string]$IdentityId
    )
    $IdentityDescriptorURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/descriptors/$IdentityId"
    $IdentityDescriptor = GetRestResult $IdentityDescriptorURL
    $IdentityDescriptor.value

}

function GetIdentity {
    Param(
        [string]$OrganizationName,
        [string]$Descriptor
    )
    $IdentityURL = "https://vssps.dev.azure.com/$OrganizationName/_apis/identities/?descriptors=$Descriptor"
    (GetRestResult $IdentityURL)[0]
}

function GetIdentityDisplayName {
    Param(
        [string]$OrganizationName,
        [string]$Descriptor
    )
    $Identity = GetIdentity $OrganizationName $Descriptor
    $IdentityDisplayName = $Identity.DisplayName

    $IdentityDisplayName
}

function GetSecurityNamespace {
    Param(
        [string]$OrganizationName,
        [string]$SecurityNamespaceId
    )
    $SecurityNamespaceURL = "https://dev.azure.com/$OrganizationName/_apis/securitynamespaces/$SecurityNamespaceId"
    (GetRestResult $SecurityNamespaceURL).value[0]
}

function GetSecurityNamespaceActions {
    Param(
        [string]$OrganizationName,
        [string]$SecurityNamespaceId,
        [int]$ACEAllow,
        [int]$ACEDeny,
        [string]$Indent
    )
    $SecurityNamespace = GetSecurityNamespace $OrganizationName $SecurityNamespaceId
    $SecurityNamespaceActions = $SecurityNamespace.actions
    ForEach ($SecurityNamespaceAction In $SecurityNamespaceActions) {
        $SecurityNamespaceActionBit = $SecurityNamespaceAction.bit
        If ($SecurityNamespaceActionBit -eq ($SecurityNamespaceActionBit -band $ACEAllow)) {
            $ACEPermission = "Allow"
        }
        ElseIf ($SecurityNamespaceActionBit -eq ($SecurityNamespaceActionBit -band $ACEDeny)) {
            $ACEPermission = "Deny"
        }
        Else {
            $ACEPermission = "Not set"
        }
        $SecurityNamespaceActionName = $SecurityNamespaceAction.name
        Write-Host "$Indent$SecurityNamespaceActionName`t$ACEPermission"
        LogWrite $LogFile "$Indent$SecurityNamespaceActionName`t$ACEPermission"
    }
}

function GetACE {
    Param(
        [string]$OrganizationName,
        [string]$ACEDescriptor,
        [string]$SecurityNamespaceId,
        [int]$ACEAllow,
        [int]$ACEDeny
    )
    $Identity = GetIdentity $OrganizationName $ACEDescriptor
    $IdentityId = $Identity.Id
    $IdentityDisplayName = $Identity.DisplayName
    $IdentityDescriptorType = $Identity.Descriptor.IdentityType
    $IdentitySId = $Identity.Descriptor.Identifier.Split(":")[2]
    #The following is working around strangeness with security groups granted permissions at TFVC root folder that do not seem to exist in the security graph
    If ($IdentityDescriptorType -eq "Microsoft.TeamFoundation.ImportedIdentity") {
        If ($IdentitySId -eq "S-1-5-21-507921405-1482476501-839522115-10835") {
            #Channel-AS
            $IdentityDescriptor = "vssgp.Uy0xLTktMTU1MTM3NDI0NS02NzY1NTA2MjktMTE0ODIyMjEwLTI5MTg4NTI4NTQtOTM3NTQ0NTk3LTEtMzg5MTY5MTAwNi0yNDMwMzc5NTg5LTIzMjM3OTkyMTMtMjQ5NDE0MDgyNA"
        }
        ElseIf ($IdentitySId -eq "S-1-5-21-507921405-1482476501-839522115-10834") {
            #Channel-IS
            $IdentityDescriptor = "vssgp.Uy0xLTktMTU1MTM3NDI0NS02NzY1NTA2MjktMTE0ODIyMjEwLTI5MTg4NTI4NTQtOTM3NTQ0NTk3LTEtMzg5MTY5MTAwNi0yNDMwMzc5NTg5LTIzMjM3OTkyMTMtMjQ5NDE0MDgyNA"
        }
        Else {
            $IdentityDescriptor = "Unknown"
        }
    }
    Else {
        $IdentityDescriptor = GetIdentityDescriptor $OrganizationName $IdentityId
    }
    $IdentityType = $IdentityDescriptor.Split(".")[0]
    Write-Host "`tACE`t$IdentityId`t$IdentityDisplayName"
    LogWrite $LogFile "`tACE`t$IdentityId`t$IdentityDisplayName"
    $Indent = "`t"
    GetSecurityNamespaceActions $OrganizationName $SecurityNamespaceId $ACEAllow $ACEDeny $Indent
    If ($IdentityType -eq "aadgp" -or $IdentityType -eq "vssgp") {
        GetGroupMembers $IdentityDescriptor $IdentityDisplayName $Indent
    }
    Else {
        GetGroupMember $IdentityDescriptor $IdentityDisplayName $Indent
    }
}

function GetACLACEs {
    Param(
        [string]$OrganizationName,
        [string]$SecurityNamespaceId,
        [string]$Token
    )
    Write-Host "ACL`t$SecurityNamepaceId`t$Token"
    LogWrite $LogFile "ACL`t$SecurityNamepaceId`t$Token"
    $ACLURL = "https://dev.azure.com/$OrganizationName/_apis/accesscontrollists/$SecurityNamespaceId`?token=$Token"
    $ACEsJson = ((GetRestResult $ACLURL).value[0].acesDictionary)
    $ACEs = @{}
    $ACEsJson.psobject.properties | ForEach { $ACEs[$_.Name] = $_.Value }
    ForEach ($Key In $ACEs.Keys) {
        $ACEDescriptor = $ACEs[$Key].descriptor
        $ACEAllow = $ACEs[$Key].allow
        $ACEDeny = $ACEs[$Key].deny
        GetACE $OrganizationName $ACEDescriptor $SecurityNamespaceId $ACEAllow $ACEDeny
    }
}

function GetProjectReleaseDefinitions {
    Param(
        [string]$OrganizationName,
        [string]$ProjectName
    )

    $ProjectReleaseDefinitionsURL = "https://vsrm.dev.azure.com/$OrganizationName/$ProjectName/_apis/release/definitions"

    (GetRestResult $ProjectReleaseDefinitionsURL).value
}

function GetProjectDeploymentApprovers {
    Param(
        [string]$OrganizationName,
        [string]$ProjectName
    )

    $ProjectId = GetProjectId $ProjectName
    Write-Host "Project`t$ProjectId`t$ProjectName"
    LogWrite $LogFile "Project`t$ProjectId`t$ProjectName"
    $ProjectReleaseDefinitions = GetProjectReleaseDefinitions $OrganizationName $ProjectName
    ForEach ($ProjectReleaseDefinition In $ProjectReleaseDefinitions) {
        $ProjectReleaseDefinitionId = $ProjectReleaseDefinition.id
        $ProjectReleaseDefinitionName = $ProjectReleaseDefinition.name
        $ProjectReleaseDefinitionURL = $ProjectReleaseDefinition.url
        Write-Host "`tReleaseDefinition`t$ProjectReleaseDefinitionId`t$ProjectReleaseDefinitionName"
        LogWrite $LogFile "`tReleaseDefinition`t$ProjectReleaseDefinitionId`t$ProjectReleaseDefinitionName"
        $ReleaseDefinition = GetRestResult $ProjectReleaseDefinitionURL
        $ReleaseDefinitionEnvironments = $ReleaseDefinition.environments
        ForEach ($ReleaseDefinitionEnvironment In $ReleaseDefinitionEnvironments) {
            $ReleaseDefinitionEnvironmentId = $ReleaseDefinitionEnvironment.id
            $ReleaseDefinitionEnvironmentName = $ReleaseDefinitionEnvironment.name
            Write-Host "`t`tReleaseDefinitionEnvironment`t$ReleaseDefinitionEnvironmentId`t$ReleaseDefinitionEnvironmentName"
            LogWrite $LogFile "`t`tReleaseDefinitionEnvironment`t$ReleaseDefinitionEnvironmentId`t$ReleaseDefinitionEnvironmentName"
            $PreDeployApprovals = $ReleaseDefinitionEnvironment.preDeployApprovals.approvals
            ForEach ($PreDeployApproval In $PreDeployApprovals) {
                $PreDeployApprovalIsAutomated = $PreDeployApproval.isAutomated
                If ($PreDeployApprovalIsAutomated -eq $False) {
                    $Approver = $PreDeployApproval.approver
                    $ApproverId = $Approver.id
                    $ApproverDisplayName = $Approver.displayName
                    $ApproverDescriptor = $Approver.descriptor
                    $ApproverIsContainer = $Approver.isContainer
                    $ApproverType = $ApproverDescriptor.Split(".")[0]
                    If ($ApproverIsContainer -eq $True) {
                        If ($ApproverType -eq "imp") {
                            $ApproverDisplayName = "[Team Foundation]\Channel-BuildMaster"
                            $ApproverDescriptor = "aadgp.Uy0xLTktMTU1MTM3NDI0NS0xMjA0NDAwOTY5LTI0MDI5ODY0MTMtMjE3OTQwODYxNi0zLTIwNjAxNjMzODEtMzgyODIxMzMxNS0yNzk3MjgwNjQ0LTE3MDUxNDg4OTI"
                            $Indent = "`t`t"
                            GetGroupMembers $ApproverDescriptor $ApproverDisplayName $Indent
                        }
                    }
                    Else {
                        $Indent = "`t"
                        GetGroupMember $ApproverDescriptor "User" $Indent
                    }
                }
                Else {
                    Write-Host "`t`t`tApprovalIsAutomated"
                    LogWrite $LogFile "`t`t`tApprovalIsAutomated"
                }
            }
        }
    }
}

#################
# MAIN
#################
#Connect-AzAccount
$LogFile = "$LogFileBasePath`_$Method`_$ProjectName`_$LogFileDateSuffix.txt"

#Initialize log files
LogInitalize $LogFile

#Write header to log file
LogWrite $LogFile "##########"
LogWrite $LogFile "Date: $LogFileDateSuffix"
LogWrite $LogFile "Team Project: $ProjectName"
LogWrite $LogFile "Method: $Method"
LogWrite $LogFile "##########"

If ($Method -eq "Projects") {
    GetProjects $OrganizationName
}
ElseIf ($Method -eq "ProjectGroupMembers") {
    GetProjectGroupMembers $OrganizationName $ProjectName
}
ElseIf ($Method -eq "ProjectTeamMembers") {
    GetProjectTeamMembers $OrganizationName $ProjectName
}
ElseIf ($Method -eq "ProjectTFVCItems") {
    GetProjectTFVCItems $OrganizationName $ProjectName
}
ElseIf ($Method -eq "ProjectRepositories") {
    GetProjectRepositories $OrganizationName $ProjectName
}
ElseIf ($Method -eq "ACLACEs") {
    If ($ProjectName -eq "YourProjectName") {
        GetACLACEs $OrganizationName "YourProjectID" "$" #VersionControlItems
        GetACLACEs $OrganizationName "YourProjectID" "$\YourProjectID" #VersionControlItems #YourProjectID = GUID from UI
    }
    Else {
        #Do nothing
    }
}
ElseIf ($Method -eq "ProjectDeploymentApprovers") {
    GetProjectDeploymentApprovers $OrganizationName $ProjectName
}
Else {
    Exit
}
