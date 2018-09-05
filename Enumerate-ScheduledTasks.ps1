Function Enumerate-ScheduledTasks
{
<#
.Synopsis

Master Function that gets all sche

Enumerate-ScheduledTasks Function: Enumerate-ScheduledTasks
Author: st0rm
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-PrivilegedSTs returns associated information of scheduled tasks to help find privilege escalation vectors.

.PARAMETER RunLevel

Filters results based on a scheduled tasks run level. Defaults to no filter, but can specify "limited" or "highest"

.PARAMETER TaskPath

Filters results based on a task's path. Defaults to all paths unless a specific path is provided. This filter accepts wildcards.

.PARAMETER TaskName

Filters results based on a task's name. Defaults to all tasks unless a specific name is provided. This filter accepts wildcards.

.PARAMETER Username

Filters results based on the user running a task. Defaults to all tasks unless a specific user is provided. This filter accepts wildcards.

.PARAMETER HasUser

Specifies that the results returned should only include tasks with an associated user.

.PARAMETER NoBuiltIn

Removes any tasks being run by BuiltIn users excluding the administrator account.

.PARAMETER GetPermissions

Also retrieves the file permissions for the application set to run by the scheduled task.

.EXAMPLE

C:\PS> Import-Module .\Enumerate-ScheduledTasks.ps1; Enumerate-ScheduledTasks

C:\PS> Import-Module .\Enumerate-ScheduledTasks.ps1; Enumerate-ScheduledTasks -NoBuiltIn $True -HasUser $True

C:\PS> Import-Module .\Enumerate-ScheduledTasks.ps1; Enumerate-ScheduledTasks -TaskName "*sometask*"

C:\PS> Import-Module .\Enumerate-ScheduledTasks.ps1; Enumerate-ScheduledTasks -TaskName "backup" -Username "*admin*" -RunLevel "Highest"

.NOTES

Get-PrivilegedSTs returns associated information of scheduled tasks to help find privilege escalation vectors.
#>

# Get All Scheduled Tasks and iterate over each task filter out results that don't match any specified filters.

    Param(
        [String]
        $RunLevel,

        [String]
        $TaskPath = "*",

        [String]
        $TaskName = "*",

        [String]
        $Username = "*",

        [Switch]
        $HasUser,

        [Switch]
        $NoBuiltIn,

        [Switch]
        $GetPermissions

    )

    $BuiltInAccounts = "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"

    $ScheduledTasksInfo = @()
    $ScheduledTasks = Get-ScheduledTask

    ForEach($ScheduledTask in $ScheduledTasks)
    {
        $NewScheduledTaskInfo = New-Object -TypeName PSObject

        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Run Level" -Value $ScheduledTask.Principal.RunLevel
        If($RunLevel -eq "Highest" -and $NewScheduledTaskInfo."Task Run Level" -ne "Highest")
        {
            Continue
        }
        ElseIf($RunLevel -eq "Limited" -and $NewScheduledTaskInfo."Task Run Level" -ne "Limited")
        {
            Continue
        }

        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Path" -Value $ScheduledTask.TaskPath
        If($NewScheduledTaskInfo."Task Path" -notlike $TaskPath)
        {
            Write-Host "TaskPath" $TaskPath
            Write-Host "ScheduledTask.TaskPath" $ScheduledTask.TaskPath
            Continue
        }

        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Name" -Value $ScheduledTask.TaskName
        If($NewScheduledTaskInfo."Task Name" -notlike $TaskName)
        {
            Continue
        }

        $NewTaskName = $NewScheduledTaskInfo."Task Path"
        $NewTaskName += $NewScheduledTaskInfo."Task Name"

        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Running as User" -Value $ScheduledTask.Principal.UserId
        If($NewScheduledTaskInfo."Task Running as User" -notlike $Username)
        {
            Continue
        }
        ElseIf($HasUser -and $Null -eq $NewScheduledTaskInfo."Task Running as User")
        {
            Continue
        }
        ElseIf($NoBuiltIn -and $BuiltInAccounts -contains $NewScheduledTaskInfo."Task Running as User")
        {
            Continue
        }
        $TaskAction = $ScheduledTask.Actions.Execute
        $TaskAction = [Environment]::ExpandEnvironmentVariables($TaskAction)
        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Action" -Value $TaskAction
        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Action Arguments" -Value $ScheduledTask.Actions.Arguments
        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Task Action Working Directory" -Value $ScheduledTask.Actions.WorkingDirectory

        $ScheduledTaskInfo = Get-ScheduledTaskInfo -TaskPath $ScheduledTask.TaskPath -TaskName $ScheduledTask.TaskName
        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Last Run Time" -Value $ScheduledTaskInfo.LastRunTime
        $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Next Run Time" -Value $ScheduledTaskInfo.NextRunTime

        Write-Host "####################################################################"
        Write-Host ""
        Write-Host $NewTaskName -ForegroundColor Green
        Write-Host ""

        $NewScheduledTaskInfo

        If($GetPermissions -and $TaskAction -ne "")
        {   
            $FirstCharacter = $TaskAction[0]
            If($FirstCharacter -eq "`"" -or $FirstCharacter -eq "'"){
                $TaskAction = $TaskAction -replace "[`"']",""
            }

            $TaskAction = Get-Command $TaskAction
            $TaskAction = $TaskAction.Source
            $Permissions = Get-Acl $TaskAction
            $Permissions = $Permissions.Access
            $NewScheduledTaskInfo | Add-Member -MemberType NoteProperty -Name "Permissions" -Value $Permissions
        }

        ForEach($Permission in $Permissions)
        {
            $Permission
        }

        Write-Host "####################################################################"
    }
}