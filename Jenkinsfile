pipeline {
    agent { label 'master' }
    triggers {
        githubPush()    
    }
    environment {
        //CONFIG
        URL_SSC = "http://10.30.100.80:8281/ssc"
        URL_SSC_API = "http://10.30.100.80:8281/ssc/api/v1"
        URL_SC_CTRL = "http://10.30.100.80:8280/scancentral-ctrl/"
        URL_DAST_API = "http://10.30.100.50:85"
        SASTToken = "fb362b85-d040-4237-9803-d6b153e449b9"
        APITokenSSC = "ZmIzNjJiODUtZDA0MC00MjM3LTk4MDMtZDZiMTUzZTQ0OWI5"

        //SAST
        APP_NAME_SSC = "IWA-Java"
        APP_VERSION_SSC = "4.0"
        urlGit = 'https://github.com/ph03nick/IWA-Java'
        
        //DAST
        cicdToken = "b52dc26f-1793-4f1c-aac2-f9eb2a4a3b32"

        //TriggerOnly
        triggerOnly = "no"
    }
    
    stages {
        stage('Git Clone') {
            agent { label 'fortify-sast-02' }
            steps {
                git branch: 'main', url: "${urlGit}"
            }
        }
        
        stage('Fortify Trigger Scan SAST') {
            agent { label 'fortify-sast-02' }
            steps {
                powershell '''
                Param (
                    $URL_SSC = $env:URL_SSC,
                    $URL_SSC_API = $env:URL_SSC_API,
                    $URL_SC_CTRL = $env:URL_SC_CTRL,
                    $SASTToken = $env:SASTToken,
                    $APITokenSSC = $env:APITokenSSC,
                    $APP_NAME_SSC = $env:APP_NAME_SSC,
                    $APP_VERSION_SSC = $env:APP_VERSION_SSC,
                    $triggerOnly = $env:triggerOnly
                )

                Write-Host ("Fortify Trigger Scan SAST!")
                $argument_list = "scancentral -url $URL_SC_CTRL start -bt mvn -upload -application $APP_NAME_SSC -version $APP_VERSION_SSC -uptoken $SASTToken"
                $output = Invoke-Expression "$argument_list"
                Write-Host ("Log: " + $output)
                
                # ==================================== Ambil Job Token ================================
                $pattern = 'Submitted job and received token:\\s+([a-f0-9\\-]+)'
                $matches = Select-String -InputObject $output -Pattern $pattern
                
                if ($matches) {
                    $token = $matches.Matches[0].Groups[1].Value
                    Write-Host "Job Token: $token"
                } else {
                    Write-Host "No match found."
                }
                
                Start-Sleep -Seconds 30
                
                # ==================================== Cek Scan Selesai ================================
                if ($triggerOnly -eq "no") {
                    $cek_sast_api = "$URL_SSC_API/cloudjobs/$token"
                    $jobState = "PENDING"
                    $projectversionid = ""
                    $selesai = "PENDING" #PENDING, SCAN_RUNNING, UPLOAD_COMPLETED
                    $Header = @{"Authorization" = "FortifyToken "+ $APITokenSSC }
                    
                    Write-Host "Sleep 30s . . ."
                    Start-Sleep -Seconds 30
                    
                    while ($selesai -eq "SCAN_RUNNING" -or $selesai -eq "PENDING") {
                        Start-Sleep -Seconds 30
                        $runstatus = Invoke-RestMethod -Method Get -Headers $Header -ContentType "application/json" -uri $cek_sast_api
                        $jobState = $runstatus.data.jobState
                        Write-Host ("Status scan: $jobState")
                        
                        if ($jobState -eq "UPLOAD_COMPLETED") {
                            $selesai = "UPLOAD_COMPLETED"
                            $projectversionid = $runstatus.data.pvId
                        }
                        
                        if ($jobState -eq "SCAN_CANCELED" -or $jobState -eq "SCAN_FAILED" ) {
                            throw "Pipeline Stop karena scan telah dihentikan"
                        }
                    }
                    
                    Write-Host ("Berhasil dengan status: $jobState")
                    Write-Host("Version App ID dari SSC: " + $projectversionid)
                    
                    # Get Severity Hasil Scan SAST
                    Write-Host "--- Get Severity Hasil Scan SAST ---"
                    $critical = 9999
                    $high = 9999
                    $cekssc = "$URL_SSC_API/projectVersions/" + $projectversionid + "/issueSummaries?seriestype=ISSUE_FRIORITY&groupaxistype=ISSUE_FRIORITY"
                    $runscan = Invoke-RestMethod -Method Get -Headers $Header -ContentType "application/json" -uri $cekssc
                    foreach ($i in $runscan.data[0].series) {
                        $issue = $i.points[0].x
                        $issueqty = $i.points[0].y
                        Write-Host ($issue + " = " + $issueqty)
                    }
                    foreach ($i in $runscan.data[0].series) {
                        $issue = $i.points[0].x
                        $issueqty = $i.points[0].y    
                        if ($issue -eq "Critical" -and $issueqty -gt $critical ) {
                            Write-Host ("link application $URL_SSC/html/ssc/version/$projectversionid/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6")
                            throw "Pipeline Stop karena terdapat temuan Critical"
                        }
                        if ($issue -eq "High" -and $issueqty -gt $high ) {
                            Write-Host ("link application $URL_SSC/html/ssc/version/$projectversionid/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6")
                            throw "Pipeline Stop karena terdapat temuan High"
                        }
                    }
                        
                    Write-Host ("--- End of Script ---")

                } elseif ($triggerOnly -eq "yes") {
                    Write-Host "Scanning Fortify SAST - Trigger Only!"
                }
                '''
            }
        }

        stage('Fortify Trigger Scan DAST') {
            agent { label 'fortify-sast-02' }
            steps {
                powershell '''
                Param (
                    $URL_DAST_API = $env:URL_DAST_API, 
                    $URL_SSC = $env:URL_SSC, 
                    $APITokenSSC = $env:APITokenSSC, 
                    $cicdToken = $env:cicdToken,
                    $triggerOnly = $env:triggerOnly
                )
            
                Write-Host "--- Start Script for Scanning Fortify DAST ---"
                Write-Host "URL_DAST_API: $URL_DAST_API"
                Write-Host "URL_SSC: $URL_SSC"
                Write-Host "APITokenSSC: $APITokenSSC"
                Write-Host "cicdToken: $cicdToken"
                
                $url_dast="$URL_DAST_API/api/v2/scans/start-scan-cicd"
                $body = @{
                    cicdToken = $cicdToken
                    name = "Scan via Jenkins"
                } | ConvertTo-Json
                
                $Header = @{"Authorization" = "FortifyToken $APITokenSSC"}
                $dastscanapp = Invoke-RestMethod -Method Post -Headers $Header -ContentType "application/json" -Body $body -uri $url_dast
                $hasil_dastscanapp = $dastscanapp.id
                Write-Host ("Scan ID: " + $hasil_dastscanapp)
                
                if ($triggerOnly -eq "no") {
                    $getstatus = "$URL_DAST_API/api/v2/scans/$hasil_dastscanapp/scan-summary"
                    $statusscan = ""
                    $selesai = 1
                    $runstatus = Invoke-RestMethod -Method Get -Headers $Header -ContentType "application/json" -uri $getstatus
                    $projectVersionId = $runstatus.item.applicationVersionId
                    $projectVersionName = $runstatus.item.applicationVersionName
                    $appn = $runstatus.item.applicationName
                    $appid = $runstatus.item.applicationId
                    $appstatscandes = $runstatus.item.scanStatusTypeDescription
                    
                    Write-Host "App Version ID: $projectVersionId"
                    Write-Host "App Version Name: $projectVersionName"
                    Write-Host "App Name: $appn"
                    Write-Host "App ID: $appid"
                    Write-Host "ScanStatus Type Desc: $appstatscandes"
                    
                    Write-Host "--- Get Status DAST ---"
                    while ($selesai -eq 1) {
                        $runstatus = Invoke-RestMethod -Method Get -Headers $Header -ContentType "application/json" -uri $getstatus
                        $statusscan = $runstatus.item.scanStatusTypeDescription
                        
                        if ($statusscan -eq "Complete" -or $statusscan -eq "Forced Complete") {
                            $selesai = 0
                        }
                        
                        if ($statusscan -eq "Pausing" -or $statusscan -eq "Paused" -or $statusscan -eq "Interrupted") {
                            throw "Pipeline Stop karena scan dihentikan"
                        }
                        
                        Write-Host ("Status scan: " + $statusscan)
                        Start-Sleep -Seconds 30
                    }
                    
                    Write-Host("Version App ID dari SSC: " + $projectVersionId)
                    Write-Host("Version App Name dari SSC: " + $projectVersionName)
                                
                    # Publish Scan Scancentral DAST
                    Write-Host "--- Publish Scan Scancentral DAST ---"
                    Start-Sleep -Seconds 15
                    $url_publishscan = "$URL_DAST_API/api/v2/scans/$hasil_dastscanapp/scan-action"
                    $badan4 = '{"ScanActionType":5}'
                    $runstatus = Invoke-RestMethod -Method Post -Headers $Header -ContentType "application/json" -Body $badan4 -uri $url_publishscan
                    Start-Sleep -Seconds 60
                	
                    # Get Severity Hasil Scan DAST
                    Write-Host "--- Get Severity Hasil Scan DAST ---"
                    $critical = 9999
                    $high = 9999
                    $cekssc = "$URL_SSC/api/v1/projectVersions/$projectVersionId/issueSummaries?seriestype=ISSUE_FRIORITY&groupaxistype=ISSUE_FRIORITY"
                    $runscan = Invoke-RestMethod -Method Get -Headers $Header -ContentType "application/json" -uri $cekssc
                    foreach ($i in $runscan.data[0].series) {
                        $issue = $i.points[0].x
                        $issueqty = $i.points[0].y
                        Write-Host ($issue + " = " + $issueqty)
                    }
                    foreach ($i in $runscan.data[0].series) {
                        $issue = $i.points[0].x
                        $issueqty = $i.points[0].y    
                        if ($issue -eq "Critical" -and $issueqty -gt $critical ) {
                            Write-Host ("link application $URL_SSC/html/ssc/version/$projectVersionId/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6")
                            throw "Pipeline Stop karena terdapat temuan Critical"
                        }
                        if ($issue -eq "High" -and $issueqty -gt $high ) {
                            Write-Host ("link application $URL_SSC/html/ssc/version/$projectVersionId/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6")
                            throw "Pipeline Stop karena terdapat temuan High"
                        }
                    }
                    Write-Host ("--- End of Script ---")
                } elseif ($triggerOnly -eq "yes") {
                    Write-Host "Scanning Fortify DAST - Trigger Only!"
                }
                '''
            }
        }
    }
}
