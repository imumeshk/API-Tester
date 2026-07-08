function New-APIForm {

    $script:lastResponseContentType = $null # Store the content type of the last response
    $script:lastResponseText = ""
    $script:lastResponseHeadersText = ""
    $script:lastResponseHeadersNormalized = @{}
    $script:currentPowerShell = $null
    $script:currentAsyncResult = $null
    
    $script:isCollectionRunning = $false
    $script:collectionRunQueue = New-Object System.Collections.Queue
    $script:collectionRunnerForm = $null
    $script:collectionRunnerGrid = $null
    $script:collectionRunnerProgress = $null
    $script:collectionRunnerSummaryLabel = $null
    $script:collectionRunnerBtnStart = $null
    $script:collectionRunnerBtnRetry = $null
    $script:collectionRunnerBtnStop = $null
    $script:collectionRunnerParentForm = $null
    $script:collectionRunTotal = 0
    # Initialize RunspacePool for background requests (Min 1, Max 5 concurrent tasks)
    $script:requestRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 5)
    $script:requestRunspacePool.Open()
    Write-Log "Runspace pool created." -Level Debug

    $script:collectionRunCompleted = 0
    $script:collectionRunDelay = 0
    $script:collectionRunStopOnFail = $false
    $script:collectionRunnerCurrentRow = $null
    $script:collectionRunStopRequested = $false
    $script:collectionRunDelayTimer = $null
    $script:cookieJar = New-Object System.Collections.ArrayList

    function Complete-CollectionRun {
        param(
            [string]$Summary = "Run Complete.",
            [bool]$EnableRetry = $true,
            [string]$PendingReason = $null
        )

        $script:isCollectionRunning = $false
        $script:collectionRunStopRequested = $false
        $script:collectionRunnerCurrentRow = $null

        if ($script:collectionRunDelayTimer) {
            try { $script:collectionRunDelayTimer.Stop() } catch {}
            try { $script:collectionRunDelayTimer.Dispose() } catch {}
            $script:collectionRunDelayTimer = $null
        }

        if ($script:collectionRunQueue) {
            if ($PendingReason) {
                foreach ($queuedRow in $script:collectionRunQueue) {
                    if ($queuedRow.Cells["Status"].Value -eq "Queued") {
                        $queuedRow.Cells["Status"].Value = "Stopped"
                        $queuedRow.Cells["Result"].Value = $PendingReason
                        $queuedRow.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#e2e3e5")
                    }
                }
            }
            $script:collectionRunQueue.Clear()
        }

        if ($script:collectionRunnerSummaryLabel) { $script:collectionRunnerSummaryLabel.Text = $Summary }
        if ($script:collectionRunnerBtnStart) { $script:collectionRunnerBtnStart.Enabled = $true; $script:collectionRunnerBtnStart.Text = "Start Run" }
        if ($script:collectionRunnerBtnRetry) { $script:collectionRunnerBtnRetry.Enabled = $EnableRetry }
        if ($script:collectionRunnerBtnStop) { $script:collectionRunnerBtnStop.Enabled = $false }

        if ($script:collectionRunnerParentForm -and $script:collectionRunnerParentForm.Tag) {
            $script:collectionRunnerParentForm.Tag.btnSubmit.Enabled = $true
            $script:collectionRunnerParentForm.Tag.btnCancel.Enabled = $false
            $script:collectionRunnerParentForm.Tag.btnRepeat.Enabled = $true
        }
    }

    function Request-CollectionRunStop {
        param([string]$Summary = "Stopping run...")

        if (-not $script:isCollectionRunning) { return }

        $script:collectionRunStopRequested = $true
        if ($script:collectionRunnerSummaryLabel) { $script:collectionRunnerSummaryLabel.Text = $Summary }
        if ($script:collectionRunnerBtnStop) { $script:collectionRunnerBtnStop.Enabled = $false }

        if ($script:collectionRunDelayTimer) {
            try { $script:collectionRunDelayTimer.Stop() } catch {}
            try { $script:collectionRunDelayTimer.Dispose() } catch {}
            $script:collectionRunDelayTimer = $null
            Complete-CollectionRun -Summary "Collection run stopped." -PendingReason "Skipped after manual stop"
            return
        }

        if ($script:currentPowerShell -and $script:currentAsyncResult -and -not $script:currentAsyncResult.IsCompleted) {
            Write-Log "Collection run stop requested. Cancelling active request."
            try { $script:currentPowerShell.Stop() } catch {}
            return
        }

        Complete-CollectionRun -Summary "Collection run stopped." -PendingReason "Skipped after manual stop"
    }

    function Handle-CollectionRunnerFormClosing {
        param(
            [object]$sender,
            [System.Windows.Forms.FormClosingEventArgs]$e
        )

        if ($e.CloseReason -in @(
            [System.Windows.Forms.CloseReason]::FormOwnerClosing,
            [System.Windows.Forms.CloseReason]::ApplicationExitCall,
            [System.Windows.Forms.CloseReason]::TaskManagerClosing,
            [System.Windows.Forms.CloseReason]::WindowsShutDown
        )) { return }

        if (-not $script:isCollectionRunning) { return }
        if ($script:collectionRunnerForm -ne $sender) { return }

        $e.Cancel = $true
        Request-CollectionRunStop -Summary "Stopping collection run..."
        if ($script:collectionRunnerSummaryLabel) {
            $script:collectionRunnerSummaryLabel.Text = "Stopping collection run... Window will stay open until the active request ends."
        }
    }

    # Create the single, persistent timer for polling request status.
    $script:requestTimer = New-Object System.Windows.Forms.Timer
    $script:requestTimer.Interval = 100 # Check every 100ms

    $script:requestTimer.Add_Tick({
        if ($script:currentAsyncResult -and $script:currentAsyncResult.IsCompleted) {
            $script:requestTimer.Stop()
            
            $jobResult = $null
            try {
                $output = $script:currentPowerShell.EndInvoke($script:currentAsyncResult)
                # Extract the result hashtable.
                $jobResult = $output | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('Success') } | Select-Object -First 1
            } catch {
                 $jobResult = @{ Success = $false; ErrorMessage = "Runspace Error: $($_.Exception.Message)" }
                 $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
            }

            # Check if it was stopped/cancelled (InvocationStateInfo might be Stopping/Stopped)
            $requestWasCancelled = $script:currentPowerShell.InvocationStateInfo.State -eq 'Stopped'
            if ($requestWasCancelled) {
                 $statusLabelStatus.Text = "Request Cancelled"
                 $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#ffc107") # Yellow/Orange
                 $richTextResponse.Text = "The request was cancelled by the user."
            }
            elseif ($jobResult) {
                if ($jobResult.Success) {
                    $res = $jobResult.Data
                    if ($script:isRepeating) { $script:repeatSuccessCount++ }
                    # Color code the status bar based on the response code
                    $statusCode = $res.StatusCode
                    if ($statusCode -ge 200 -and $statusCode -le 299) {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#28a745") # Green
                    }
                    elseif ($statusCode -ge 300 -and $statusCode -le 399) {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#ffc107") # Yellow
                    }
                    else { # 4xx, 5xx, etc.
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
                    }
                    $statusLabelStatus.Text = "$($res.StatusCode) $($res.StatusDescription)"
                    $statusLabelTime.Text = "Time: $($res.ElapsedTime) ms"
                    $statusLabelSize.Text = "Size: $(if ($res.RawContentLength -gt 0) { Format-Bytes -bytes $res.RawContentLength } else { (if ($res.Content) { Format-Bytes -bytes $res.Content.Length } else { '0 bytes' }) })"
                    Write-Log "Response: $($res.StatusCode) $($res.StatusDescription)"

                    $headersBuilder = New-Object System.Text.StringBuilder
                    foreach ($key in $res.Headers.Keys) { $headersBuilder.AppendLine("${key}: $($res.Headers[$key])") | Out-Null }
                    $responseHeadersText = $headersBuilder.ToString()
                    $richTextResponseHeaders.Text = $responseHeadersText
                    $script:lastResponseHeadersText = $responseHeadersText

                    # Normalize response headers to lowercase keys for consistent lookups.
                    $headersNormalized = @{}
                    foreach ($k in $res.Headers.Keys) { $headersNormalized[$k.ToLower()] = $res.Headers[$k] }
                    $script:lastResponseHeadersNormalized = $headersNormalized

                    $contentType = ""
                    $script:lastResponseContentType = $null # Reset content type
                    if ($headersNormalized.ContainsKey('content-type')) { $contentType = $headersNormalized['content-type'].Split(';')[0].Trim() }
                    $script:lastResponseContentType = $contentType

                    if ($script:settings.LogLevel -eq 'Debug') {
                        # Log Cookies
                        if ($jobResult.Cookies) {
                            $cookieLog = "Received Cookies:`r`n"
                            foreach ($c in $jobResult.Cookies) {
                                $cookieLog += "$($c.Name)=$($c.Value) (Domain: $($c.Domain))`r`n"
                            }
                            Write-Log $cookieLog
                        }

                        Write-Log "Response Headers:`r`n$responseHeadersText"
                        $shouldLogBody = $true
                        if ($contentType -match 'text|rtf|json|html|xml') { $shouldLogBody = $false }
                        if ($shouldLogBody -and $res.Content) {
                            $debugBody = [System.Text.Encoding]::UTF8.GetString($res.Content)
                            if ($debugBody.Length -gt 10000) { $debugBody = $debugBody.Substring(0, 10000) + "... (truncated)" }
                            Write-Log "Response Body:`r`n$debugBody"
                        }
                    }

                    # Update Cookie Jar
                    if ($jobResult.Cookies) {
                        foreach ($newCookie in $jobResult.Cookies) {
                            # Remove existing cookie with same name/domain/path
                            $existing = $null
                            foreach ($c in $script:cookieJar) {
                                if ($c.Name -eq $newCookie.Name -and $c.Domain -eq $newCookie.Domain -and $c.Path -eq $newCookie.Path) {
                                    $existing = $c
                                    break
                                }
                            }
                            if ($existing) { $script:cookieJar.Remove($existing) }
                            
                            # Add if not expired
                            if (-not $newCookie.Expired) {
                                [void]$script:cookieJar.Add($newCookie)
                            }
                        }
                    }

                    $isAttachmentHeader = $headersNormalized.ContainsKey('content-disposition') -and $headersNormalized['content-disposition'] -like 'attachment*'
                    
                    # Determine if the content is something we can render as text.
                    $isRenderable = $contentType -like 'text/*' -or 
                                    $contentType -like 'application/json*' -or 
                                    $contentType -like 'application/xml*' -or
                                    $contentType -like 'application/xml*' -or 
                                    $contentType -like 'application/rtf*' -or
                                    $contentType -like 'image/*' -or
                                    $contentType -like 'text/html*'

                    # Store the content type for the prettify button
                    $script:lastResponseContentType = $contentType
                    $script:btnExportResponse.Enabled = $isRenderable
                    $script:btnPrettifyResponse.Enabled = $isRenderable

                    $finalSavePath = $null

                    $isBinaryResponse = (-not $isRenderable -and $res.Content.Length -gt 0)
                    if ($isBinaryResponse -or $isAttachmentHeader) { # Check if we should try to save the file
                        if ($script:settings.AutoSaveToFile -and [System.IO.Directory]::Exists($script:settings.AutoSavePath)) { # Auto-save is enabled
                            # Auto-Save is enabled.
                            $targetFolder = $script:settings.AutoSavePath
                            $fileNameFromHeader = $null
                            if ($headersNormalized.ContainsKey('content-disposition') -and $headersNormalized['content-disposition'] -match 'filename="?([^"]+)"?') {
                                $fileNameFromHeader = $matches[1] # Extract filename from header
                            }
                            
                            if ($fileNameFromHeader) {
                                $outputFileName = $fileNameFromHeader # Start with filename from header
                                # Apply auto-rename logic if enabled.
                                if ($script:settings.AutoRenameFile) {
                                    # Find all keys in the form body that correspond to file uploads.
                                    $fileUploads = @($script:formBody.GetEnumerator() | Where-Object { $_.Value -is [hashtable] -and $_.Value.ContainsKey('_Path') })

                                    $prefix = if ($script:settings.EnableAutoRenamePrefix) { $script:settings.AutoRenamePrefix } else { "" }
                                    $ext = [System.IO.Path]::GetExtension($outputFileName)

                                    if ($fileUploads.Count -eq 1) {
                                        $file = $fileUploads[0].Value
                                        $name = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                                        $outputFileName = "$prefix$name$ext"
                                    } elseif ($fileUploads.Count -ge 2) {
                                        $file1 = $fileUploads[0].Value
                                        $file2 = $fileUploads[1].Value
                                        $name1 = [System.IO.Path]::GetFileNameWithoutExtension($file1.Name)
                                        $name2 = [System.IO.Path]::GetFileNameWithoutExtension($file2.Name)
                                        $outputFileName = "$prefix$name1 and $name2$ext"
                                    }
                                }
                                $finalSavePath = Join-Path -Path $targetFolder -ChildPath $outputFileName
                            } else {
                                $richTextResponse.Text = "Auto-save is enabled, but the server response did not include a 'filename' in the Content-Disposition header. Cannot save the file."
                            }
                        } elseif (-not [string]::IsNullOrWhiteSpace($script:textOutputFile.Text)) {
                            # Manual output file is specified.
                            $finalSavePath = $script:textOutputFile.Text
                        }
                    }
                    if ($finalSavePath) { # If a save path was determined, write the file
                        try {
                            $parentDir = [System.IO.Path]::GetDirectoryName($finalSavePath)
                            if (-not (Test-Path $parentDir)) { [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null }
                            [System.IO.File]::WriteAllBytes($finalSavePath, $res.Content)
                            Write-Log "Saved file to $finalSavePath"
                            $uri = New-Object System.Uri $finalSavePath
                            $richTextResponse.Text = "Binary response successfully saved to:`n$($uri.AbsoluteUri)"
                            $script:lastResponseText = ""
                        } catch {
                            $richTextResponse.Text = "Error saving file to '$finalSavePath':`n$($_.Exception.Message)"
                            Write-Log "Error saving file: $($_.Exception.Message)" -Level Info
                            $script:lastResponseText = ""
                        }
                    } elseif ($isRenderable -or $res.Content.Length -eq 0) { # If not saving, try to render it
                        $responseContent = if ($res.Content) { [System.Text.Encoding]::UTF8.GetString($res.Content) } else { "" }
                        $script:lastResponseText = $responseContent
                        $tabControlResponse.TabPages.Remove($tabPreview) # Remove preview tab by default
                        $webBrowserPreview.Visible = $false
                        $pictureBoxPreview.Visible = $false

                        try {
                        if ($contentType -like 'application/rtf*') {
                            $richTextResponse.Rtf = $responseContent
                            Write-Log "Rendering response as RTF."
                        } elseif ($contentType -like 'application/json*') {
                            $jsonObj = $responseContent | ConvertFrom-Json # Validate JSON
                            Populate-JsonTree -JsonData $jsonObj -NodesCollection $treeViewJson.Nodes
                            $richTextResponse.Rtf = Format-JsonAsRtf -JsonString $responseContent -FontSize $script:settings.ResponseFontSize
                            Write-Log "Rendering response as formatted JSON."
                        } elseif ($contentType -like 'application/xml*' -or $contentType -like 'text/xml*') {
                        # Check if the JSON is a redline document
                        if ($jsonBodyForTest -and $jsonBodyForTest._type -eq 'redlinedocument') {
                            $richTextResponse.Rtf = Format-RedlineAsRtf -RedlineJson $jsonBodyForTest -FontSize $script:settings.ResponseFontSize
                            Write-Log "Rendering response as a formatted Redline Document."
                        }
                            $richTextResponse.Text = ([xml]$responseContent).OuterXml # Format XML
                            Write-Log "Rendering response as formatted XML."
                        } elseif ($contentType -like 'text/html*') {
                                $webBrowserPreview.Visible = $true
                                $webBrowserPreview.DocumentText = $responseContent
                                $tabControlResponse.TabPages.Add($tabPreview) # Add preview tab
                                $richTextResponse.Text = $responseContent # Also show raw text
                                Write-Log "Rendering response as HTML."
                            } elseif ($contentType -like 'image/*') {
                                $ms = New-Object System.IO.MemoryStream(,$res.Content)
                                $pictureBoxPreview.Image = [System.Drawing.Image]::FromStream($ms)
                                $pictureBoxPreview.Visible = $true
                                $tabControlResponse.TabPages.Add($tabPreview)
                                $richTextResponse.Text = "[Binary Image Data: $contentType]"
                                Write-Log "Rendering response as Image."
                            } else {
                                # Fallback for other text-based types
                                $richTextResponse.Text = $responseContent
                            }
                        }
                        catch { 
                            $richTextResponse.Text = $responseContent 
                            Write-Log "Failed to render rich content, showing as plain text."
                        }
                        # Execute user-defined tests against the response.
                        if (-not [string]::IsNullOrWhiteSpace($testsRaw)) {
                            $script:testResults.Clear()
                            $testScriptBlock = [scriptblock]::Create($testsRaw)

                            $jsonBodyForTest = $null
                            try {
                                if (-not $finalSavePath) {
                                    $jsonBodyForTest = [System.Text.Encoding]::UTF8.GetString($res.Content) | ConvertFrom-Json -ErrorAction Stop
                                }
                            } catch {
                                # If JSON parsing fails, $jsonBodyForTest will remain $null.
                            }

                            $testScopeVars = @{
                                statusCode = $res.StatusCode
                                headers    = $res.Headers
                                body       = if ($finalSavePath) { "[Binary content saved to file]" } else { [System.Text.Encoding]::UTF8.GetString($res.Content) }
                                jsonBody   = $jsonBodyForTest
                            }

                            try {
                            # Define the functions within the scope of the Invoke-Command
                            $fullTestScript = @"
                            $(Get-Command Assert-Equal | Select-Object -ExpandProperty Definition)
                            $(Get-Command Assert-Contains | Select-Object -ExpandProperty Definition)
                            $(Get-Command Assert-StatusIs | Select-Object -ExpandProperty Definition)
                            $testsRaw
"@
                            Invoke-Command -ScriptBlock ([scriptblock]::Create($fullTestScript)) -ArgumentList $testScopeVars -NoNewScope -ErrorAction Stop
                            } catch {
                                $script:testResults.Add([PSCustomObject]@{ Status = 'ERROR'; Message = "Test script failed to execute: $($_.Exception.Message)"}) | Out-Null
                            }

                            $richTextTestResults.Rtf = Format-TestResultsAsRtf -Results $script:testResults -FontSize $script:settings.ResponseFontSize
                            $tabControlResponse.SelectedTab = $tabTestResults
                        }
                    } else { # This is now the case for unrenderable binary content with no save path
                        $richTextResponse.Text = "Cannot render binary response in the UI.`n`nContent-Type: $contentType`nSize: $(Format-Bytes -bytes $res.Content.Length)`n`nTo save this response, specify an 'Output File' or enable 'Auto-Save' and send the request again."
                        $script:lastResponseText = ""
                    }
                }
                elseif ($jobResult) { # This handles the case where the job did not succeed
                    # Job failed but we might still have error data
                    if ($script:isRepeating) { $script:repeatFailCount++ }
                    $res = $jobResult.Data
                    if ($res -and $res.errorBody) {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
                        if ($res.StatusCode) {
                            $statusLabelStatus.Text = "$($res.StatusCode) $($res.StatusDescription)"
                        } else {
                            $statusLabelStatus.Text = "Request Failed"
                        }
                        $statusLabelTime.Text = "Time: $($res.ElapsedTime) ms" # Display elapsed time even on error
                        $statusLabelSize.Text = "Size: $(if (($res.RawContentLength -as [int64]) -gt 0) { Format-Bytes -bytes ([int64]$res.RawContentLength) } else { if ($res.errorBody) { Format-Bytes -bytes ([System.Text.Encoding]::UTF8.GetByteCount($res.errorBody)) } else { '0 bytes' } })"

                        $headersBuilder = New-Object System.Text.StringBuilder
                        $headersNormalized = @{}
                        if ($res.Headers) {
                            foreach ($key in $res.Headers.Keys) {
                                $headersBuilder.AppendLine("${key}: $($res.Headers[$key])") | Out-Null
                                $headersNormalized[$key.ToLower()] = $res.Headers[$key]
                            }
                        }
                        $responseHeadersText = $headersBuilder.ToString()
                        $richTextResponseHeaders.Text = $responseHeadersText
                        $script:lastResponseHeadersText = $responseHeadersText
                        $script:lastResponseHeadersNormalized = $headersNormalized

                        $contentType = ""
                        if ($headersNormalized.ContainsKey('content-type')) { $contentType = $headersNormalized['content-type'].Split(';')[0].Trim() }
                        $script:lastResponseContentType = $contentType

                        try {
                            $null = $res.errorBody | ConvertFrom-Json
                            $richTextResponse.Rtf = Format-JsonAsRtf -JsonString $res.errorBody -FontSize $script:settings.ResponseFontSize
                        } catch {
                            $richTextResponse.Text = $res.errorBody
                        }
                        $script:lastResponseText = $res.errorBody
                    } else {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
                        $statusLabelStatus.Text = "Request Failed"
                        $richTextResponseHeaders.Text = ""
                        $script:lastResponseHeadersText = ""
                        $script:lastResponseHeadersNormalized = @{}
                        $richTextResponse.Text = $jobResult.ErrorMessage # Display generic job error message
                        $script:lastResponseText = $jobResult.ErrorMessage
                    }
                }

            }
            
            # Cleanup Runspace
            if ($script:currentPowerShell) { $script:currentPowerShell.Dispose() }
            $script:currentPowerShell = $null
            $script:currentAsyncResult = $null
            
            # --- Collection Runner Logic ---
            if ($script:isCollectionRunning) {
                $script:collectionRunCompleted++
                if ($script:collectionRunnerProgress) { $script:collectionRunnerProgress.Value = $script:collectionRunCompleted }
                if ($script:collectionRunnerSummaryLabel) { $script:collectionRunnerSummaryLabel.Text = "Progress: $($script:collectionRunCompleted)/$($script:collectionRunTotal)" }

                # Update Grid Status
                if ($script:collectionRunnerCurrentRow) {
                    $row = $script:collectionRunnerCurrentRow
                    if ($requestWasCancelled -and $script:collectionRunStopRequested) {
                        $row.Cells["Status"].Value = "Stopped"
                        $row.Cells["Result"].Value = "Cancelled by user"
                        $row.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#e2e3e5")
                    } elseif ($jobResult.Success) {
                        $row.Cells["Status"].Value = "PASS"
                        $row.Cells["Result"].Value = "$($jobResult.Data.StatusCode) $($jobResult.Data.StatusDescription)"
                        $row.Cells["Time"].Value = $jobResult.Data.ElapsedTime
                        $row.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#d4edda")
                    } else {
                        $row.Cells["Status"].Value = "FAIL"
                        $row.Cells["Result"].Value = if ($jobResult.Data) { "$($jobResult.Data.StatusCode) $($jobResult.Data.StatusDescription)" } else { $jobResult.ErrorMessage }
                        $row.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#f8d7da")
                    }
                    # Test Summary
                    if ($script:testResults) {
                        $passCount = ($script:testResults | Where-Object { $_.Status -eq 'PASS' }).Count
                        $failCount = ($script:testResults | Where-Object { $_.Status -ne 'PASS' }).Count
                        $row.Cells["Tests"].Value = "$passCount passed, $failCount failed"
                    }
                }

                if ($script:collectionRunStopRequested) {
                    Complete-CollectionRun -Summary "Collection run stopped." -PendingReason "Skipped after manual stop"
                    return
                }

                # Stop on Failure Check
                $isFailure = (-not $jobResult.Success) -or ($jobResult.Data.StatusCode -ge 400)
                if ($script:collectionRunStopOnFail -and $isFailure) {
                    Complete-CollectionRun -Summary "Stopped due to failure." -EnableRetry $true -PendingReason "Skipped after failure"
                    return
                }

                if ($script:collectionRunQueue.Count -gt 0) {
                    $nextRow = $script:collectionRunQueue.Dequeue()
                    $script:collectionRunnerCurrentRow = $nextRow
                    $nextRow.Cells["Status"].Value = "Running..."
                    
                    # Delay Logic
                    $delay = [Math]::Max(50, $script:collectionRunDelay)
                    $script:collectionRunDelayTimer = New-Object System.Windows.Forms.Timer
                    $script:collectionRunDelayTimer.Interval = $delay
                    $script:collectionRunDelayTimer.Add_Tick({
                        param($s, $ev)
                        $s.Stop(); $s.Dispose()
                        $script:collectionRunDelayTimer = $null
                        if ($script:collectionRunStopRequested) {
                            Complete-CollectionRun -Summary "Collection run stopped." -PendingReason "Skipped after manual stop"
                            return
                        }
                        $currentRow = $script:collectionRunnerCurrentRow
                        $requestObject = if ($currentRow) { Get-RequestObjectFromItem -Item $currentRow.Tag } else { $null }
                        if (-not $requestObject) {
                            if ($currentRow) {
                                $currentRow.Cells["Status"].Value = "ERROR"
                                $currentRow.Cells["Result"].Value = "Missing request data"
                                $currentRow.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#f8d7da")
                            }
                            Complete-CollectionRun -Summary "Run stopped because a request entry is missing request data." -EnableRetry $true -PendingReason "Skipped after missing request data"
                            return
                        }
                        Load-Request-From-Object -RequestObject $requestObject
                        Invoke-RequestExecution
                    })
                    $script:collectionRunDelayTimer.Start()
                    return # Exit tick to wait for delay
                } else {
                    Complete-CollectionRun -Summary "Run Complete." -EnableRetry $true
                }
            }

            # Handle repeat requests *after* cleaning up the completed runspace.
            if ($script:isRepeating -eq $true) {
                $script:currentRepeatIteration++
                if ($script:currentRepeatIteration -lt $script:repeatCount) {
                    Write-Log "Repeat Request: Iteration $($script:currentRepeatIteration) of $($script:repeatCount) completed. Sending next request..." -Level Debug
                    $statusLabelStatus.Text = "Repeating Request ($($script:currentRepeatIteration + 1)/$($script:repeatCount))... (Success: $($script:repeatSuccessCount), Fail: $($script:repeatFailCount))"
                    
                    $repeatDelayTimer = New-Object System.Windows.Forms.Timer
                    $repeatDelayTimer.Interval = 200 # A small delay to allow UI to update
                    $repeatDelayBlock = { 
                        param($sender, $e) # Use param block to get the timer object that fired the event
                        Invoke-RequestExecution # Call the core logic directly, bypassing the button click
                        $sender.Stop() # Stop and dispose the timer using the sender parameter
                        $sender.Dispose()
                    }
                    $repeatDelayTimer.Add_Tick($repeatDelayBlock)
                    $repeatDelayTimer.Start()
                    return # Exit the main timer tick; the delay timer will fire the next request.
                } else {
                    # All repeats are done
                    $finalStatus = "Repeat Request Completed ($($script:repeatCount) iterations). Success: $($script:repeatSuccessCount), Fail: $($script:repeatFailCount)."
                    Write-Log $finalStatus -Level Info
                    $statusLabelStatus.Text = $finalStatus
                    $script:isRepeating = $false
                }
            }
            
            # This code runs if not repeating, or if the last repeat has just finished.
            if (-not $script:isCollectionRunning) {
                $btnSubmit.Enabled = $true; $btnSubmit.BackColor = $script:Theme.PrimaryButton
                $btnCancel.Enabled = $false
                $btnRepeat.Enabled = $true
            }
        }
    })

# This function contains the core logic for preparing and executing an API request.
# It's separated from the UI button's click event to allow for programmatic re-triggering (e.g., for repeating requests).
function Invoke-RequestExecution {
    $missingUiControls = @(
        @{ Name = 'comboMethod'; Control = $script:comboMethod }
        @{ Name = 'comboBodyType'; Control = $script:comboBodyType }
        @{ Name = 'comboEnvironment'; Control = $script:comboEnvironment }
        @{ Name = 'textUrl'; Control = $script:textUrl }
        @{ Name = 'textHeaders'; Control = $script:textHeaders }
        @{ Name = 'textBody'; Control = $script:textBody }
        @{ Name = 'textTests'; Control = $script:textTests }
    ) | Where-Object { -not $_.Control } | ForEach-Object { $_.Name }

    if ($missingUiControls.Count -gt 0) {
        $missingList = $missingUiControls -join ', '
        Write-Log "Invoke-RequestExecution skipped because UI is not ready. Missing controls: $missingList"
        if ($statusLabelStatus) { $statusLabelStatus.Text = "Request UI is still loading." }
        return
    }

    # Clear previous response and test results.
    $richTextResponse.Text = ""
    $richTextResponseHeaders.Text = ""
    $richTextCode.Text = ""
    $treeViewJson.Nodes.Clear()
    $script:btnExportResponse.Enabled = $false # Disable export button for new request
    $script:btnPrettifyResponse.Enabled = $false # Disable prettify button for new request
    $richTextTestResults.Text = ""
    $script:lastResponseText = ""
    $script:lastResponseHeadersText = ""
    $script:lastResponseHeadersNormalized = @{}

    # Reset the status bar for the new request.
    if (-not $script:isCollectionRunning) {
        $statusStrip.BackColor = $script:Theme.PrimaryButton
    }
    $statusLabelStatus.Text = "Sending request..."
    $statusLabelTime.Text = "Time: ..."
    $statusLabelSize.Text = "Size: ..."
    $form.Refresh() # Force UI update
    Write-Log "Request execution started."
    
    # Substitute environment variables into all relevant fields.
    $script:activeEnvironment = $script:comboEnvironment.SelectedItem

    # --- Pre-request Script Execution ---
    if ($script:textPreRequest -and -not [string]::IsNullOrWhiteSpace($script:textPreRequest.Text)) {
        try {
            Write-Log "Executing Pre-request script..."
            if ($script:activeEnvironment -ne "No Environment" -and $script:environments.ContainsKey($script:activeEnvironment)) {
                $Environment = $script:environments[$script:activeEnvironment]
            } else { $Environment = @{} }
            
            Invoke-Command -ScriptBlock ([scriptblock]::Create($script:textPreRequest.Text)) -NoNewScope
            Write-Log "Pre-request script executed successfully."
        } catch {
            Write-Log "Pre-request script failed: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show("Pre-request script failed:`n$($_.Exception.Message)", "Error", "OK", "Error")
            # Re-enable buttons on script failure
            $btnSubmit.Enabled = $true; $btnCancel.Enabled = $false; $btnRepeat.Enabled = $true; return
        }
    }

    $selectedMethod = if ($script:comboMethod.SelectedItem) { [string]$script:comboMethod.SelectedItem } else { "GET" }
    $selectedBodyType = if ($script:comboBodyType.SelectedItem) { [string]$script:comboBodyType.SelectedItem } else { "text/plain" }
    $method = (Substitute-Variables -InputString $selectedMethod)
    $url = (Substitute-Variables -InputString $script:textUrl.Text)
    $headersRaw = (Substitute-Variables -InputString $script:textHeaders.Text)
    $bodyRaw = (Substitute-Variables -InputString $script:textBody.Text)
    $testsRaw = $script:textTests.Text

    # --- GraphQL Logic ---
    if ($selectedBodyType -eq "GraphQL") {
        $gqlQuery = (Substitute-Variables -InputString $script:txtGqlQuery.Text)
        $gqlVars = (Substitute-Variables -InputString $script:txtGqlVars.Text)
        $payload = @{ query = $gqlQuery }
        if (-not [string]::IsNullOrWhiteSpace($gqlVars)) {
            try { $payload['variables'] = $gqlVars | ConvertFrom-Json } catch { Write-Log "Invalid GraphQL Variables JSON" }
        }
        $bodyRaw = $payload | ConvertTo-Json -Depth 10
        $bodyType = "application/json" # Send as JSON
        $method = "POST" # GraphQL is typically POST
    }

    $outputFormat = if ($script:textOutputFormat) { [string]$script:textOutputFormat.Text } else { "" }
    $outputFormat = $outputFormat.Trim()
    $outputFormatKey = "outputFormat"
    $outputFormatValue = $outputFormat
    if ($outputFormat -match '^\s*([^=]+?)\s*=\s*(.+)\s*$') {
        $outputFormatKey = $matches[1].Trim()
        $outputFormatValue = $matches[2].Trim()
    }
    if ($selectedBodyType -ne "GraphQL") { 
        $bodyType = $selectedBodyType
    }
    # Determine the correct output path based on whether Auto-Save is enabled.
    if ($script:settings.AutoSaveToFile) {
        $outputFile = $script:settings.AutoSavePath # Use the path from settings
    } else {
        $outputFile = $script:textOutputFile.Text
    }
    
    $includeFilename = $checkIncludeFilename.Checked
    $includeContentType = $checkIncludeContentType.Checked
    
    $ignoreSsl = $script:settings.IgnoreSslErrors
    $timeoutSeconds = $script:settings.RequestTimeoutSeconds
    
    # Store request state for code generation
    $script:lastRequestState = [PSCustomObject]@{
        Method = $method
        Url = $url
        Headers = $headersRaw
        Body = $bodyRaw
        BodyType = $bodyType
    }

    Write-Log "URL: $url"
    Write-Log "Headers: $headersRaw"
    Write-Log "Method: $method"
    Write-Log "Request Body: $bodyRaw" -Level Info
    Write-Log "Output Format: $outputFormat"

    if ($outputFile) {
        if ($script:settings.AutoSaveToFile) { Write-Log "Auto-Save Folder specified: $outputFile" }
        else { Write-Log "Output File specified: $outputFile" }
    }

    if (-not $url) {
    Write-Log "URL is empty. Showing message box."
    [System.Windows.Forms.MessageBox]::Show("Please enter a valid URL.")
    return
    }

    # Only add to history on the first request of a repeat sequence, or for a normal request.
    if ($script:settings.EnableHistory -and -not $script:isRepeating -and -not $script:isCollectionRunning) {
        # Create and save a history entry for the current request.
        $historyEntry = [PSCustomObject]@{
            Timestamp = Get-Date
            Method    = $method
            Url       = $url
            Headers   = $headersRaw
            Body      = $bodyRaw
            BodyType  = $bodyType
            OutputFormat = $outputFormat
            Tests     = $testsRaw
            PreRequestScript = $script:textPreRequest.Text
            Environment = $script:comboEnvironment.SelectedItem
            Authentication = (& $script:authPanel.GetAuthData) # Use the helper to get auth data
        }
        $script:history = @($historyEntry) + $script:history
        if ($script:history.Count -gt 50) { $script:history = $script:history[0..49] }
        
        $listHistory.Items.Insert(0, "$($historyEntry.Timestamp.ToString('HH:mm:ss')) | $($historyEntry.Method) | $($historyEntry.Url)")
        if ($listHistory.Items.Count -gt 50) { $listHistory.Items.RemoveAt(50) }

        Save-History
    }

    # Parse user-provided headers from the textbox into a hashtable.
    $headers = @{}
    foreach ($line in $headersRaw -split "`n") {
    if ($line -match "^\s*(.+?):\s*(.+)$") {
        $headers[$matches[1]] = $matches[2]
    }
    }

    # Apply authentication details to the request headers or URL.
    $authHeader = $null
    $currentAuth = & $script:authPanel.GetAuthData
    switch ($currentAuth.Type) {
        "Auth2" {
            # Pre-flight check for token expiry
            $tokenIsExpired = $false
            if ($currentAuth.TokenExpiryTimestamp) {
                try {
                    $expiryTime = [datetime]$currentAuth.TokenExpiryTimestamp
                    if ([DateTime]::UtcNow -ge $expiryTime) {
                        $tokenIsExpired = $true
                    }
                } catch {
                    Write-Log "Could not parse Auth2 TokenExpiryTimestamp: $($currentAuth.TokenExpiryTimestamp)" -Level Info
                }
            }

            if ($tokenIsExpired -and -not [string]::IsNullOrWhiteSpace($currentAuth.RefreshToken)) {
                Write-Log "Auth2 access token expired. Attempting to refresh..." -Level Info
                try {
                    $refreshBody = @{
                        grant_type    = 'refresh_token'
                        refresh_token = $currentAuth.RefreshToken
                        client_id     = $currentAuth.ClientId
                        client_secret = $currentAuth.ClientSecret # Some providers require this
                    }
                    $tokenResponse = Invoke-RestMethod -Uri $currentAuth.TokenEndpoint -Method Post -Body $refreshBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                    
                    # Update UI and current auth data with the new token
                    $currentAuth.AccessToken = $tokenResponse.access_token
                    $script:authPanel.TextAuth2AccessToken.Text = $tokenResponse.access_token
                    
                    if ($tokenResponse.PSObject.Properties.Name -contains 'refresh_token') {
                        $currentAuth.RefreshToken = $tokenResponse.refresh_token
                        $script:authPanel.TextAuth2RefreshToken.Text = $tokenResponse.refresh_token
                    }
                    
                    $currentAuth.TokenExpiryTimestamp = ([DateTime]::UtcNow).AddSeconds([int]$tokenResponse.expires_in)
                    $script:authPanel.TextAuth2AccessToken.Tag = $currentAuth.TokenExpiryTimestamp
                    
                    Write-Log "Auth2 token successfully refreshed." -Level Info
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Failed to automatically refresh access token. Please get a new token manually.`n`nError: $($_.Exception.Message)", "Token Refresh Failed", "OK", "Error")
                  # Stop the request by re-enabling the submit button and returning #FIX: Corrected comment
                  $btnSubmit.Enabled = $true; $btnCancel.Enabled = $false; $btnRepeat.Enabled = $true; return
                }
            }
        }
        "API Key" {
            if (-not ([string]::IsNullOrWhiteSpace($currentAuth.Key) -or [string]::IsNullOrWhiteSpace($currentAuth.Value))) { #FIX: Corrected condition
                if ($currentAuth.AddTo -eq "Header") {
                    $headers[$currentAuth.Key] = $currentAuth.Value
                } else { # Query Params
                    $separator = if ($url -like '*?*') { '&' } else { '?' }
                    $url += "$separator$([uri]::EscapeDataString($currentAuth.Key))=$([uri]::EscapeDataString($currentAuth.Value))"
                }
            }
        }
        "Bearer Token" {
            if (-not [string]::IsNullOrWhiteSpace($currentAuth.Token)) { # Only add if token is not empty
                $authHeader = "Bearer $($currentAuth.Token)"
            }
        }
        "Basic Auth" {
            if (-not ([string]::IsNullOrWhiteSpace($currentAuth.Username))) { # Only add if username is not empty
                $credentials = [System.Text.Encoding]::UTF8.GetBytes("$($currentAuth.Username):$($currentAuth.Password)")
                $authHeader = "Basic $([System.Convert]::ToBase64String($credentials))"
            }
        }
    } # End of switch ($currentAuth.Type)
    
    # Client Certificate Logic (Prepare data for job)
    $clientCertData = $null
    if ($currentAuth.Type -eq "Client Certificate") {
        $clientCertData = @{
            Source = $currentAuth.Source
            Path = $currentAuth.Path
            Password = $currentAuth.Password
            Thumbprint = $currentAuth.Thumbprint
        }
    }

    if ($authHeader) { $headers["Authorization"] = $authHeader }
    
    # Construct the request body
    $script:formBody = @{}
    $script:formBody.Clear() # Clear any data from a previous request
    if ($bodyType -eq "multipart/form-data") {
        Write-Log "Parsing Body as multipart/form-data..."
        foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) { # Process non-empty lines
            if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                $key = $matches[1].Trim()
                $filePath = if ($matches[3]) { $matches[3] } else { $matches[4] } # Correctly get path if quoted (group 3) or not (group 4)
                $attributesRaw = $matches[5]

                if (Test-Path $filePath) {
                    # Pass a simple hashtable with path/name/metadata so it serializes safely across Start-Job.
                    $fileObject = @{
                        _Path = $filePath
                        Name  = ([System.IO.Path]::GetFileName($filePath))
                        IncludeFilename = $false # Default to false, check attributes
                        IncludeContentType = $false # Default to false, check attributes
                    }
                    if ($attributesRaw -match 'filename=([^;`\r`n]+)') {
                        $fileObject.Name = $matches[1].Trim() # Override filename from attribute
                        $fileObject.IncludeFilename = $true
                    }
                    if ($attributesRaw -match 'type=([^;`\r`n]+)') {
                        $fileObject.ContentType = $matches[1].Trim() # Override content type from attribute
                        $fileObject.IncludeContentType = $true
                    }
                    # If the global checkbox is checked but no type attribute was specified, get it now.
                    if ($includeContentType -and -not $fileObject.ContainsKey('ContentType')) {
                        $fileObject.ContentType = Get-MimeType -filePath $filePath
                    }
                    
                    $script:formBody[$key] = $fileObject
                    Write-Log "Adding file to form: '$filePath' as key '$key'"
                } else {
                    Write-Log "File not found, skipping: '$filePath'"
                }
            } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') { # Regular key-value (allow empty values)
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $script:formBody[$key] = $value
                Write-Log "Adding form value: '$key' = '$value'"
            }
        }
    if ($outputFormatValue) {
        $script:formBody[$outputFormatKey] = $outputFormatValue
    }
    }

    # Generate Code Snippet
    $selectedLang = if ($script:comboCodeLanguage.SelectedItem) { $script:comboCodeLanguage.SelectedItem } else { "cURL" }
    $richTextCode.Text = Generate-CodeSnippet -RequestItem $script:lastRequestState -Language $selectedLang

    if ($script:settings.LogLevel -eq 'Debug') {
        $debugCurl = Generate-CodeSnippet -RequestItem $script:lastRequestState -Language "cURL"
        Write-Log "Generated cURL:`r`n$debugCurl"
    }

    # --- Build multipart body bytes on the main thread to avoid Start-Job serialization issues ---
    $multipartBytes = $null # Initialize
    $multipartContentType = $null # Initialize
    if ($bodyType -eq "multipart/form-data") {
        $boundary = "---------------------------" + [System.Guid]::NewGuid().ToString("N")
        $encoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        function Write-To-StreamLocal { param([System.IO.MemoryStream]$s, [string]$t) $b = $encoding.GetBytes($t); $s.Write($b,0,$b.Length) }
        $ms = New-Object System.IO.MemoryStream
        foreach ($key in $script:formBody.Keys) {
            $val = $script:formBody[$key]
            Write-To-StreamLocal -s $ms -t "--$boundary`r`n"
            if ($val -is [hashtable] -and $val.ContainsKey('_Path')) {
                $fp = $val._Path
                $fn = if ($val.ContainsKey('Name')) { $val.Name } else { [System.IO.Path]::GetFileName($fp) }
                $ctype = if ($val.ContainsKey('ContentType')) { $val.ContentType } else { 'application/octet-stream' }
                $disp = "Content-Disposition: form-data; name=`"$key`"; filename=`"$fn`"`r`n"
                Write-To-StreamLocal -s $ms -t $disp
                Write-To-StreamLocal -s $ms -t "Content-Type: $ctype`r`n`r`n"
                $fb = [System.IO.File]::ReadAllBytes($fp)
                $ms.Write($fb,0,$fb.Length)
                Write-To-StreamLocal -s $ms -t "`r`n"
            } else {
                $field = [string]$val
                Write-To-StreamLocal -s $ms -t "Content-Disposition: form-data; name=`"$key`"`r`n`r`n$field`r`n"
            }
        } # End of foreach ($key in $script:formBody.Keys)
        Write-To-StreamLocal -s $ms -t "--$boundary--`r`n"
        $ms.Seek(0,'Begin') | Out-Null
        $multipartBytes = $ms.ToArray()
        $multipartContentType = "multipart/form-data; boundary=$boundary"
        $ms.Close()
    }

    # Prepare Cookies for Job
    $inputCookies = @()
    if ($script:cookieJar.Count -gt 0) {
        $uri = New-Object System.Uri($url)
        foreach ($c in $script:cookieJar) {
            # Simple domain matching
            if ($uri.Host.EndsWith($c.Domain.TrimStart('.')) -or $c.Domain.TrimStart('.') -eq $uri.Host) {
                $inputCookies += $c
            }
        }
    }
    $proxySettings = @{ Mode=$script:settings.ProxyMode; Address=$script:settings.ProxyAddress; Port=$script:settings.ProxyPort; User=$script:settings.ProxyUser; Pass=$script:settings.ProxyPass }
    
    # This script block is executed in a background job to keep the UI responsive.
    $scriptBlock = { #region Start-Job ScriptBlock 
        param($url, $method, $headers, $bodyRaw, $bodyType, $formBody, $outputFile, $includeFilename, $includeContentType, $outputFormat, $multipartBytes, $multipartContentType, $ignoreSsl, $timeoutSeconds, $proxySettings, $clientCertData, $inputCookies)

        function Format-Bytes {
            param([long]$bytes)
            if ($bytes -lt 0) { return "N/A" }
            $units = @("B", "KB", "MB", "GB", "TB")
            $i = 0
            $size = [double]$bytes
            while ($size -ge 1024 -and $i -lt ($units.Length - 1)) {
                $size /= 1024
                $i++
            }
            return "{0:N2} {1}" -f $size, $units[$i]
        }
        $result = @{ Success = $false; Data = $null; ErrorMessage = "" }
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
          function Job-Log { param([string]$Message) Write-Verbose "JOB: $Message" } # Use Verbose to avoid polluting output
            Job-Log "Starting request to $url"

            if ($ignoreSsl) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }

          $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method = $method
            $req.Timeout = $timeoutSeconds * 1000
            
            # Proxy Configuration
            if ($proxySettings.Mode -eq 'Custom') {
                $proxy = New-Object System.Net.WebProxy($proxySettings.Address, $proxySettings.Port)
                if ($proxySettings.User) {
                    $proxy.Credentials = New-Object System.Net.NetworkCredential($proxySettings.User, $proxySettings.Pass)
                }
                $req.Proxy = $proxy
            } elseif ($proxySettings.Mode -eq 'None') {
                $req.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
            } else {
                $req.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
                $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            }

            # Client Certificates
            if ($clientCertData) {
                if ($clientCertData.Source -eq "PFX File" -and (Test-Path $clientCertData.Path)) {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($clientCertData.Path, $clientCertData.Password)
                    [void]$req.ClientCertificates.Add($cert)
                } elseif ($clientCertData.Source -eq "User Store") {
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
                    $store.Open("ReadOnly")
                    $certs = $store.Certificates.Find("FindByThumbprint", $clientCertData.Thumbprint, $false)
                    if ($certs.Count -gt 0) { [void]$req.ClientCertificates.Add($certs[0]) }
                    $store.Close()
                }
            }

            # Cookies
            $req.CookieContainer = New-Object System.Net.CookieContainer
            if ($inputCookies) {
                foreach ($c in $inputCookies) {
                    # Reconstruct cookie to ensure it attaches to container
                    $req.CookieContainer.Add($c)
                }
            }

            foreach ($key in $headers.Keys) { 
                if ($key -ne 'Content-Type') { # Content-Type is set automatically for body, avoid double-setting
                    $req.Headers.Add($key, $headers[$key]) 
                }
            }

            # Only attempt to write a request body for methods that support it.
            if ($method -in @('POST', 'PUT', 'PATCH')) {
                if ($bodyType -eq "multipart/form-data" -and $multipartBytes) {
                    $req.ContentType = $multipartContentType
                    $req.ContentLength = $multipartBytes.Length
                    Job-Log "Writing prebuilt multipart body, $($multipartBytes.Length) bytes"
                    $rs = $req.GetRequestStream()
                    $rs.Write($multipartBytes, 0, $multipartBytes.Length)
                    $rs.Close()
                } elseif ($bodyType -eq "multipart/form-data") {
                    Job-Log "Multipart Form-Data Logic: No bytes"
                } else {
                    if (-not [string]::IsNullOrEmpty($bodyRaw)) {
                        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyRaw)
                        $req.ContentLength = $bodyBytes.Length
                        $req.ContentType = if ($headers.ContainsKey('Content-Type')) { $headers['Content-Type'] } else { $bodyType }
                        Job-Log "Request ContentLength (raw) = $($req.ContentLength) bytes"
                        $requestStream = $req.GetRequestStream()
                        $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
                        $requestStream.Close()
                    }
                } # End of if (-not [string]::IsNullOrEmpty($bodyRaw))
            } # End of body-writing logic

            $response = $req.GetResponse()
            $stopwatch.Stop()

            $responseStream = $response.GetResponseStream()
            $memStream = New-Object System.IO.MemoryStream
            $responseStream.Close()
          $responseHeaders = @{}
          foreach ($key in $response.Headers.AllKeys) { $responseHeaders[$key] = $response.Headers[$key] }
          
          $resCookies = $req.CookieContainer.GetCookies($req.RequestUri)
            $memStream.Close()
            $responseHeaders = @{}
            foreach ($key in $response.Headers.AllKeys) { $responseHeaders[$key] = $response.Headers[$key] }
            
            $resCookies = $req.CookieContainer.GetCookies($req.RequestUri)
            $result.Success = $true
            $result.Data = @{
                StatusCode        = [int]$response.StatusCode
                StatusDescription = $response.StatusDescription
                ElapsedTime       = $stopwatch.ElapsedMilliseconds
                Headers           = $responseHeaders
                Content           = $responseBytes
                Cookies           = $resCookies
                RawContentLength  = $response.ContentLength
            }
        } # End of try
        catch {
            $stopwatch.Stop()
            $result.ErrorMessage = $_.Exception.Message
            if ($_.Exception.Response) {
                $errorBody = ""
                $errorHeaders = @{}
                foreach ($key in $_.Exception.Response.Headers.AllKeys) { $errorHeaders[$key] = $_.Exception.Response.Headers[$key] }
                if ($errorStream = $_.Exception.Response.GetResponseStream()) {
                    $reader = New-Object System.IO.StreamReader($errorStream)
                    $errorBody = $reader.ReadToEnd()
                    $reader.Close()
                    $errorStream.Close()
                }
                $result.Data = @{
                    StatusCode        = [int]$_.Exception.Response.StatusCode
                    StatusDescription = $_.Exception.Response.StatusDescription
                    ElapsedTime       = $stopwatch.ElapsedMilliseconds
                    Headers           = $errorHeaders
                    RawContentLength  = $_.Exception.Response.ContentLength
                    errorBody         = $errorBody
                }
            } else {
                $result.Data = @{ ElapsedTime = $stopwatch.ElapsedMilliseconds }
            }
        } # End of catch
        return $result
    } #endregion

    # Use Runspace (PowerShell instance) instead of Start-Job for better performance
    if ($script:currentPowerShell) { $script:currentPowerShell.Dispose(); $script:currentPowerShell = $null }
    $script:currentPowerShell = [PowerShell]::Create()
    $script:currentPowerShell.AddScript($scriptBlock).AddArgument($url).AddArgument($method).AddArgument($headers).AddArgument($bodyRaw).AddArgument($bodyType).AddArgument($formBody).AddArgument($outputFile).AddArgument($includeFilename).AddArgument($includeContentType).AddArgument($outputFormat).AddArgument($multipartBytes).AddArgument($multipartContentType).AddArgument($ignoreSsl).AddArgument($timeoutSeconds).AddArgument($proxySettings).AddArgument($clientCertData).AddArgument($inputCookies) | Out-Null
    
    $script:currentAsyncResult = $script:currentPowerShell.BeginInvoke()

    $script:requestTimer.Start()
}

    # --- Collection Runner Window ---
    function Show-CollectionRunnerWindow {
        param(
            [PSCustomObject]$Item,
            [System.Windows.Forms.Form]$parentForm
        )

        $runnerForm = New-Object System.Windows.Forms.Form -Property @{
            Text          = "Collection Runner: $($Item.Name)"
            Size          = New-Object System.Drawing.Size(900, 700)
            StartPosition = "CenterParent"
            BackColor     = $script:Theme.FormBackground
        }

        # --- Layout ---
        $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
            Dock        = 'Fill'
            ColumnCount = 1
            RowCount    = 3
            Padding     = [System.Windows.Forms.Padding]::new(10)
        }
        $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
        $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
        $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

        # --- Top Panel (Summary & Progress) ---
        $topPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; ColumnCount = 2; RowCount = 2 }
        $topPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
        $topPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

        $summaryLabel = New-Label -Text "Ready to run." -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 10); TextAlign = 'MiddleLeft' }
        $progress = New-Object System.Windows.Forms.ProgressBar -Property @{ Dock = 'Fill'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 5) }
        
        # Settings Panel
        $settingsPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; FlowDirection = 'LeftToRight'; WrapContents = $false }
        $lblDelay = New-Label -Text "Delay (ms):" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 5, 5, 0) }
        $numDelay = New-Object System.Windows.Forms.NumericUpDown -Property @{ Minimum = 0; Maximum = 60000; Value = 0; Width = 60 }
        if ($script:settings -and $script:settings['CollectionRunnerDelay']) { $numDelay.Value = $script:settings['CollectionRunnerDelay'] }
        $chkStopOnFail = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Stop on Failure"; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(15, 3, 0, 0) }
        if ($script:settings -and $script:settings['CollectionRunnerStopOnFail']) { $chkStopOnFail.Checked = $script:settings['CollectionRunnerStopOnFail'] }
        $chkSelectAll = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Select All"; Checked = $true; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(15, 3, 0, 0) }
        
        $settingsPanel.Controls.AddRange(@($lblDelay, $numDelay, $chkStopOnFail, $chkSelectAll))

        $topPanel.Controls.Add($summaryLabel, 0, 0)
        $topPanel.Controls.Add($settingsPanel, 1, 0)
        $topPanel.Controls.Add($progress, 0, 1); $topPanel.SetColumnSpan($progress, 2)

        # --- Grid ---
        $grid = New-Object System.Windows.Forms.DataGridView -Property @{
            Dock               = 'Fill'
            ReadOnly           = $true
            AllowUserToAddRows = $false
            RowHeadersVisible  = $false
            SelectionMode      = 'FullRowSelect'
            BackgroundColor    = $script:Theme.GroupBackground
            BorderStyle        = 'None'
        }
        $colCheck = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
        $colCheck.HeaderText = ""
        $colCheck.Name = "Run"
        $colCheck.Width = 30
        $grid.Columns.Add($colCheck) | Out-Null
        
        $grid.Columns.Add("Name", "Request") | Out-Null
        $grid.Columns.Add("Status", "Status") | Out-Null
        $grid.Columns.Add("Result", "Result") | Out-Null
        $grid.Columns.Add("Time", "Time (ms)") | Out-Null
        $grid.Columns.Add("Tests", "Tests") | Out-Null
        $grid.Columns["Name"].AutoSizeMode = 'Fill'
        $grid.Columns["Result"].Width = 200

        # --- Bottom Panel (Buttons) ---
        $bottomPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'RightToLeft'; Dock = 'Fill'; AutoSize = $true }
        $btnStart = New-Button -Text "Start Run" -Style 'Primary' -Property @{ Width = 120; Height = 35 }
        $btnClose = New-Button -Text "Close" -Style 'Secondary' -Property @{ Width = 100; Height = 35 } -OnClick { $this.FindForm().Close() }
        $btnStop = New-Button -Text "Stop Run" -Style 'Danger' -Property @{ Width = 120; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,5,0); Enabled = $false } -OnClick {
            Request-CollectionRunStop
        }
        $btnRetry = New-Button -Text "Retry Failed" -Style 'Secondary' -Property @{ Width = 120; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,5,0); Enabled = $false }
        $btnExport = New-Button -Text "Export CSV" -Style 'Secondary' -Property @{ Width = 100; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,5,0) }
        $bottomPanel.Controls.AddRange(@($btnStart, $btnClose, $btnExport, $btnRetry, $btnStop))

        $runnerState = [PSCustomObject]@{
            form = $runnerForm
            parentForm = $parentForm
            grid = $grid
            progress = $progress
            summaryLabel = $summaryLabel
            btnStart = $btnStart
            btnRetry = $btnRetry
            btnStop = $btnStop
            btnExport = $btnExport
            numDelay = $numDelay
            chkStopOnFail = $chkStopOnFail
            chkSelectAll = $chkSelectAll
        }
        $btnStart.Tag = $runnerState
        $btnRetry.Tag = $runnerState
        $btnExport.Tag = $runnerState
        $chkSelectAll.Tag = $runnerState

        $btnRetry.Add_Click({
            $state = $this.Tag
            $failedRows = @()
            foreach ($row in $state.grid.Rows) {
                if ($row.Cells["Status"].Value -in @("FAIL", "ERROR")) { $failedRows += $row }
            }

            if ($failedRows.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No failed requests to retry.", "Info", "OK", "Information")
                return
            }

            if ($script:collectionRunQueue -eq $null) { $script:collectionRunQueue = New-Object System.Collections.Queue }
            $script:collectionRunQueue.Clear()
            foreach ($row in $failedRows) {
                $script:collectionRunQueue.Enqueue($row)
                $row.Cells["Status"].Value = "Queued"
                $row.Cells["Result"].Value = ""
                $row.Cells["Time"].Value = ""
                $row.Cells["Tests"].Value = ""
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
            }

            if ($script:settings) {
                $script:settings.CollectionRunnerDelay = [int]$state.numDelay.Value
                $script:settings.CollectionRunnerStopOnFail = $state.chkStopOnFail.Checked
                Save-Settings
            }

            $script:isCollectionRunning = $true
            $script:collectionRunDelay = [int]$state.numDelay.Value
            $script:collectionRunStopOnFail = $state.chkStopOnFail.Checked
            $script:collectionRunnerForm = $state.form
            $script:collectionRunnerGrid = $state.grid
            $script:collectionRunnerProgress = $state.progress
            $script:collectionRunnerSummaryLabel = $state.summaryLabel
            $script:collectionRunnerBtnStart = $state.btnStart
            $script:collectionRunnerBtnRetry = $state.btnRetry
            $script:collectionRunnerBtnStop = $state.btnStop
            $script:collectionRunnerParentForm = $state.parentForm
            $script:collectionRunTotal = $script:collectionRunQueue.Count
            $script:collectionRunCompleted = 0
            $script:collectionRunPassed = 0
            $script:collectionRunFailed = 0
            $script:collectionRunStopRequested = $false

            $script:collectionRunnerProgress.Maximum = [Math]::Max(1, $script:collectionRunTotal)
            $script:collectionRunnerProgress.Value = 0
            $script:collectionRunnerSummaryLabel.Text = "Retrying $($script:collectionRunTotal) failed requests..."
            $script:collectionRunnerBtnStart.Enabled = $false
            $script:collectionRunnerBtnRetry.Enabled = $false
            $script:collectionRunnerBtnStop.Enabled = $true

            if ($script:collectionRunQueue.Count -gt 0) {
                $firstRow = $script:collectionRunQueue.Dequeue()
                $script:collectionRunnerCurrentRow = $firstRow
                $firstRow.Cells["Status"].Value = "Running..."
                $requestObject = Get-RequestObjectFromItem -Item $firstRow.Tag
                if (-not $requestObject) {
                    $firstRow.Cells["Status"].Value = "ERROR"
                    $firstRow.Cells["Result"].Value = "Missing request data"
                    $firstRow.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#f8d7da")
                    Complete-CollectionRun -Summary "Unable to retry one or more requests because request data is missing." -EnableRetry $true
                    return
                }
                Load-Request-From-Object -RequestObject $requestObject
                $state.parentForm.Tag.btnSubmit.Enabled = $false
                $state.parentForm.Tag.btnCancel.Enabled = $true
                $state.parentForm.Tag.btnRepeat.Enabled = $false
                Invoke-RequestExecution
            }
        })

        $btnExport.Add_Click({
            $state = $this.Tag
            $sfd = New-Object System.Windows.Forms.SaveFileDialog
            $sfd.Filter = "CSV Files (*.csv)|*.csv"
            $sfd.FileName = "collection_run_results.csv"
            if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $results = @()
                foreach ($row in $state.grid.Rows) {
                    $results += [PSCustomObject]@{
                        Request = $row.Cells["Name"].Value
                        Status  = $row.Cells["Status"].Value
                        Result  = $row.Cells["Result"].Value
                        TimeMs  = $row.Cells["Time"].Value
                        Tests   = $row.Cells["Tests"].Value
                    }
                }
                $results | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Export successful.", "Export", "OK", "Information")
            }
        })

        $chkSelectAll.Add_CheckedChanged({
            $state = $this.Tag
            foreach ($row in $state.grid.Rows) { $row.Cells["Run"].Value = $this.Checked }
        })

        # --- Logic ---
        function Get-RequestsRecursive {
            param($NodeItem)
            $requests = @()
            if ($NodeItem.Type -eq "Request") {
                $requests += $NodeItem
            } elseif ($NodeItem.Items) {
                foreach ($child in $NodeItem.Items) {
                    $requests += Get-RequestsRecursive -NodeItem $child
                }
            }
            return $requests
        }
        $allRequests = Get-RequestsRecursive -NodeItem $Item

        # Populate Grid
        $grid.Rows.Clear()
        foreach ($req in $allRequests) {
            $rowIndex = $grid.Rows.Add(@($true, $req.Name, "Queued", "", "", ""))
            $grid.Rows[$rowIndex].Tag = $req
        }

        $btnStart.Add_Click({
            $state = $this.Tag
            # Reset state
            if ($script:collectionRunQueue -eq $null) { $script:collectionRunQueue = New-Object System.Collections.Queue }
            $script:collectionRunQueue.Clear()
            
            foreach ($row in $state.grid.Rows) {
                $requestObject = Get-RequestObjectFromItem -Item $row.Tag
                if ($row.Cells["Run"].Value -and $requestObject) {
                    $script:collectionRunQueue.Enqueue($row)
                    $row.Cells["Status"].Value = "Queued"
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
                } elseif ($row.Cells["Run"].Value) {
                    $row.Cells["Status"].Value = "Invalid"
                    $row.Cells["Result"].Value = "Missing request data"
                    $row.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#fff3cd")
                } else {
                    $row.Cells["Status"].Value = "Skipped"
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGray
                }
                if ($row.Cells["Status"].Value -ne "Invalid") { $row.Cells["Result"].Value = "" }
                $row.Cells["Time"].Value = ""
                $row.Cells["Tests"].Value = ""
            }

            if ($script:settings) {
                $script:settings.CollectionRunnerDelay = [int]$state.numDelay.Value
                $script:settings.CollectionRunnerStopOnFail = $state.chkStopOnFail.Checked
                Save-Settings
            }

            $script:isCollectionRunning = $true
            $script:collectionRunDelay = [int]$state.numDelay.Value
            $script:collectionRunStopOnFail = $state.chkStopOnFail.Checked
            
            $script:collectionRunnerForm = $state.form
            $script:collectionRunnerGrid = $state.grid
            $script:collectionRunnerProgress = $state.progress
            $script:collectionRunnerSummaryLabel = $state.summaryLabel
            $script:collectionRunnerBtnStart = $state.btnStart
            $script:collectionRunnerBtnRetry = $state.btnRetry
            $script:collectionRunnerBtnStop = $state.btnStop
            $script:collectionRunnerParentForm = $state.parentForm
            $script:collectionRunTotal = $script:collectionRunQueue.Count
            $script:collectionRunCompleted = 0
            $script:collectionRunPassed = 0
            $script:collectionRunFailed = 0
            $script:collectionRunStopRequested = $false

            # Reset UI
            $script:collectionRunnerProgress.Maximum = [Math]::Max(1, $script:collectionRunTotal)
            $script:collectionRunnerProgress.Value = 0
            $script:collectionRunnerSummaryLabel.Text = "Starting run..."

            # Disable button
            $this.Enabled = $false
            $script:collectionRunnerBtnRetry.Enabled = $false
            $script:collectionRunnerBtnStop.Enabled = $true
            $this.Text = "Running..."

            # Dequeue and run the first request
            if ($script:collectionRunQueue.Count -gt 0) {
                $firstRow = $script:collectionRunQueue.Dequeue()
                $script:collectionRunnerCurrentRow = $firstRow
                $firstRow.Cells["Status"].Value = "Running..."
                $requestObject = Get-RequestObjectFromItem -Item $firstRow.Tag
                if (-not $requestObject) {
                    $firstRow.Cells["Status"].Value = "ERROR"
                    $firstRow.Cells["Result"].Value = "Missing request data"
                    $firstRow.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#f8d7da")
                    Complete-CollectionRun -Summary "Unable to start one or more requests because request data is missing." -EnableRetry $true
                    return
                }
                Load-Request-From-Object -RequestObject $requestObject
                
                # Control main form buttons
                $state.parentForm.Tag.btnSubmit.Enabled = $false
                $state.parentForm.Tag.btnCancel.Enabled = $true
                $state.parentForm.Tag.btnRepeat.Enabled = $false
                
                Invoke-RequestExecution
            } else {
                # No requests to run
                Complete-CollectionRun -Summary "No runnable requests found in this collection/folder." -EnableRetry $true
            }
        })

        # Assemble form
        $mainLayout.Controls.Add($topPanel, 0, 0)
        $mainLayout.Controls.Add($grid, 0, 1)
        $mainLayout.Controls.Add($bottomPanel, 0, 2)
        $runnerForm.Controls.Add($mainLayout)
        $runnerForm.Add_FormClosing({ param($sender, $e) Handle-CollectionRunnerFormClosing -sender $sender -e $e })

        $runnerForm.Show($parentForm) # Show non-modally
    }

    $script:monitorPool = $null
    $script:isHistoryUndocked = $false
    $script:lastDockState = 'Bottom' # Initialize the last known dock state
    $script:responseForm = $null # Initialize the undocked response form variable
    $script:isMainFormClosing = $false # New flag to indicate if the main form is closing
    if ($script:settings.EnableHistory) {
        Load-History
    } #FIX: Corrected Load-History call
    Load-Settings
    Load-RequestTemplates
    Load-RequestTabs
    Load-Globals
    Load-Environments
    Load-Monitors
    Load-Collections

    # Initialize dock state from loaded settings, ensuring it's a valid state
    $script:responseDockState = $script:settings.ResponseDockState

    # Create Form
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text               = "PowerShell API Tester v$($script:AppVersion)"
        Size               = New-Object System.Drawing.Size(1200, 1000)
        StartPosition      = "CenterScreen"
        MinimumSize        = New-Object System.Drawing.Size(900, 800)
        FormBorderStyle    = [System.Windows.Forms.FormBorderStyle]::Sizable
        KeyPreview         = $true
        BackColor          = $script:Theme.FormBackground
    }

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $script:monitorJobs = @{} # Hash to store running monitor jobs

    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $statusLabelStatus = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{
        Spring      = $true
        Text        = "Ready"
        TextAlign   = [System.Drawing.ContentAlignment]::MiddleLeft
    }
    $statusLabelTime = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{
        Text = "Time: N/A"
    }
    $statusLabelSize = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{
        Text = "Size: N/A"
    }
    $statusStrip.BackColor = $script:Theme.PrimaryButton
    $statusLabelStatus.ForeColor = $statusLabelTime.ForeColor = $statusLabelSize.ForeColor = $script:Theme.PrimaryButtonText

    $statusStrip.Items.AddRange(@($statusLabelStatus, $statusLabelTime, $statusLabelSize))

    # --- Menu Strip and File Menu ---
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Menu")
    $toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Tools")
    $monitorMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Monitor")
    $menuStrip.BackColor = $script:Theme.GroupBackground
    $menuStrip.ForeColor = $script:Theme.TextColor


    # Initialize RunspacePool for background monitoring (Min 1, Max 5 concurrent tasks)
    $script:monitorPool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 5)
    $script:monitorPool.Open()

    # --- Monitoring System ---
    $notifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $notifyIcon.Icon = [System.Drawing.SystemIcons]::Application
    $notifyIcon.Visible = $true
    $notifyIcon.Text = "API Tester Monitor"

    $monitorTimer = New-Object System.Windows.Forms.Timer
    $monitorTimer.Interval = 1000 # Tick every second
    $monitorTimer.Add_Tick({
        $now = Get-Date
        foreach ($m in $script:monitors) {
            if ($m.Status -eq 'Running') {
                $lastRun = if ($m.LastRun) { [DateTime]$m.LastRun } else { [DateTime]::MinValue }
                
                # Check if it's time to run (and not currently running)
                if (($now - $lastRun).TotalSeconds -ge $m.IntervalSeconds -and -not $script:monitorJobs.ContainsKey($m.Id)) {
                    
                    # Start Monitor Job
                    $m.LastRun = $now
                    
                    # Simplified job script block for monitoring
                    $jobBlock = {
                        param($url, $method, $headers, $body, $bodyType, $timeout) #FIX: Corrected parameter definition
                        try {
                            $sw = [System.Diagnostics.Stopwatch]::StartNew()
                            $req = [System.Net.HttpWebRequest]::Create($url)
                            $req.Method = $method
                            $req.Timeout = $timeout * 1000
                            # Add headers/body logic here (simplified for brevity)
                            $resp = $req.GetResponse()
                            $sw.Stop()
                            return @{ Success=$true; StatusCode=[int]$resp.StatusCode; Time=$sw.ElapsedMilliseconds; Msg="OK" }
                        } catch {
                            return @{ Success=$false; StatusCode=0; Time=0; Msg=$_.Exception.Message }
                        }
                    }
                    
                    $ps = [PowerShell]::Create()
                    $ps.RunspacePool = $script:monitorPool
                    $ps.AddScript($jobBlock).AddArgument($m.Request.Url).AddArgument($m.Request.Method).AddArgument($m.Request.Headers).AddArgument($m.Request.Body).AddArgument($m.Request.BodyType).AddArgument($m.Request.RequestTimeoutSeconds) | Out-Null #FIX: Corrected argument list
                    $script:monitorJobs[$m.Id] = @{ PS = $ps; AR = $ps.BeginInvoke() }
                }
            }
        }

        # Check running jobs
        $ids = @($script:monitorJobs.Keys)
        foreach ($id in $ids) {
            $entry = $script:monitorJobs[$id]
            if ($entry.AR.IsCompleted) {
                $res = $entry.PS.EndInvoke($entry.AR) | Select-Object -First 1
                $entry.PS.Dispose()
                $script:monitorJobs.Remove($id)
                
                # Alerting Logic
                $mon = ($script:monitors | Where-Object {$_.Id -eq $id})
                if ($mon) {
                    # Log to CSV
                    try {
                        $logEntry = [PSCustomObject]@{
                            Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            MonitorName = $mon.Name
                            URL         = $mon.Request.Url
                            Success     = $res.Success
                            StatusCode  = $res.StatusCode
                            TimeMs      = $res.Time
                            Message     = $res.Msg
                        }
                        $logEntry | Export-Csv -Path $monitorLogFilePath -Append -NoTypeInformation -Force
                    } catch { Write-Log "Failed to write to monitor log: $($_.Exception.Message)" -Level Info }

                    $alertMsg = $null
                    $alertType = $null
                    if ($mon.Alerts.OnFailure -and (-not $res.Success -or $res.StatusCode -ne 200)) {
                        $alertMsg = "$($mon.Name) Failed: $($res.Msg)"
                        $alertType = "Failure"
                        $notifyIcon.ShowBalloonTip(5000, "API Monitor Alert", $alertMsg, [System.Windows.Forms.ToolTipIcon]::Error)
                    } elseif ($mon.Alerts.OnSlow -and $res.Time -gt $mon.Alerts.ThresholdMs) {
                        $alertMsg = "$($mon.Name) Slow: $($res.Time)ms"
                        $alertType = "Slow"
                        $notifyIcon.ShowBalloonTip(5000, "API Monitor Warning", $alertMsg, [System.Windows.Forms.ToolTipIcon]::Warning)
                    }

                    # Email Alert
                    if ($alertMsg -and $mon.Alerts.SendEmail -and $mon.Alerts.EmailTo -and $script:settings.MonitorSmtpServer) {
                        try {
                            $alertData = @{
                                MonitorName = $mon.Name
                                Status = $alertType
                                StatusCode = $res.StatusCode
                                Url = $mon.Request.Url
                                TimeMs = $res.Time
                                Message = $res.Msg
                                Timestamp = $logEntry.Timestamp
                            }
                            $subjectTemplate = if ($script:settings.MonitorAlertSubjectTemplate) { $script:settings.MonitorAlertSubjectTemplate } else { "API Alert: {MonitorName}" }
                            $bodyTemplate = if ($script:settings.MonitorAlertBodyTemplate) { $script:settings.MonitorAlertBodyTemplate } else { $alertMsg }
                            $emailSubject = Format-AlertTemplate -Template $subjectTemplate -Data $alertData
                            $emailBody = Format-AlertTemplate -Template $bodyTemplate -Data $alertData
                            if ([string]::IsNullOrWhiteSpace($emailSubject)) { $emailSubject = "API Alert: $($mon.Name)" }
                            if ([string]::IsNullOrWhiteSpace($emailBody)) { $emailBody = $alertMsg }

                            if ($script:settings.MonitorSmtpAuthMethod -eq "OAuth2") {
                                # Check for refresh
                                if ($script:settings.MonitorSmtpRefreshToken -and $script:settings.MonitorSmtpTokenEndpoint) {
                                     $shouldRefresh = $false
                                     if ($script:settings.MonitorSmtpTokenExpiry) {
                                         if ([DateTime]::UtcNow -ge [DateTime]$script:settings.MonitorSmtpTokenExpiry) { $shouldRefresh = $true }
                                     } elseif (-not $script:settings.MonitorSmtpPass) { $shouldRefresh = $true }
                                     if ($shouldRefresh) { Refresh-SmtpToken }
                                }
                                $isHtml = $script:settings.MonitorAlertBodyForceHtml -or (Test-IsHtmlBody -Body $emailBody)
                                Send-SmtpOAuth2 -Server $script:settings.MonitorSmtpServer -Port $script:settings.MonitorSmtpPort -UseSsl $script:settings.MonitorSmtpUseSsl -From $script:settings.MonitorSmtpFrom -To $mon.Alerts.EmailTo -Subject $emailSubject -Body $emailBody -User $script:settings.MonitorSmtpUser -AccessToken $script:settings.MonitorSmtpPass -IsHtml:$isHtml
                            } else {
                                $smtpParams = @{
                                    SmtpServer = $script:settings.MonitorSmtpServer
                                    Port = $script:settings.MonitorSmtpPort
                                    UseSsl = $script:settings.MonitorSmtpUseSsl
                                    From = $script:settings.MonitorSmtpFrom
                                    To = $mon.Alerts.EmailTo
                                    Subject = $emailSubject
                                    Body = $emailBody
                                    IsBodyHtml = ($script:settings.MonitorAlertBodyForceHtml -or (Test-IsHtmlBody -Body $emailBody))
                                }
                                if ($script:settings.MonitorSmtpUser) {
                                    $pass = $script:settings.MonitorSmtpPass | ConvertTo-SecureString -AsPlainText -Force
                                    $smtpParams.Credential = New-Object System.Management.Automation.PSCredential($script:settings.MonitorSmtpUser, $pass)
                                }
                                Send-MailMessage @smtpParams -ErrorAction Stop
                            }
                        } catch { Write-Log "Failed to send email alert: $($_.Exception.Message)" -Level Info }
                    }

                    # Analytics Webhook
                    if ($mon.AnalyticsUrl) {
                        try {
                            $payload = @{
                                monitorName = $mon.Name
                                timestamp = $logEntry.Timestamp
                                success = $res.Success
                                statusCode = $res.StatusCode
                                timeMs = $res.Time
                                message = $res.Msg
                            } | ConvertTo-Json -Compress
                            Invoke-RestMethod -Uri $mon.AnalyticsUrl -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop
                        } catch { Write-Log "Failed to send analytics for $($mon.Name): $($_.Exception.Message)" -Level Info }
                    }
                }
            }
        }
    })
    $monitorTimer.Start()

    # --- Import/Export Workspace ---
    $importCurlMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import cURL...", $null, {
        $curlForm = New-Object System.Windows.Forms.Form -Property @{
            Text = "Import cURL"
            Size = New-Object System.Drawing.Size(600, 450)
            StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        }
        $labelCurl = New-Label -Text "Paste cURL command here:" -Property @{ Dock = "Top"; Height = 25; Padding = [System.Windows.Forms.Padding]::new(5) }
        $txtCurl = New-TextBox -Multiline $true -Property @{ Dock = "Fill"; ScrollBars = "Vertical"; Font = New-Object System.Drawing.Font("Courier New", 9) }
        
        $panelBtn = New-Object System.Windows.Forms.Panel -Property @{ Dock = "Bottom"; Height = 40; Padding = [System.Windows.Forms.Padding]::new(5) }
        $btnImport = New-Button -Text "Import" -Property @{ Dock = "Right"; Width = 100 } -OnClick {
            $raw = $txtCurl.Text
            if ([string]::IsNullOrWhiteSpace($raw)) { return }

            # Basic parsing logic for standard cURL commands
            $url = ""
            $method = "GET"
            $headers = @{}
            $body = ""

            # Regex to find URL (http/https) inside quotes or whitespace
            if ($raw -match "['`"](https?://[^'`"]+)['`"]") { $url = $matches[1] }
            elseif ($raw -match "(https?://\S+)") { $url = $matches[1] }

            # Method
            if ($raw -match "-X\s+([A-Z]+)") { $method = $matches[1] }
            
            # Headers (-H "Key: Value")
            # Regex matches -H, space, quote (group 1), content (group 2), matching quote (backreference 1)
            $hMatches = [regex]::Matches($raw, '-H\s+([''"])(.*?)\1')
            foreach ($m in $hMatches) {
                $headerContent = $m.Groups[2].Value
                if ($headerContent -match "^(.*?):\s*(.*)$") {
                    $k = $matches[1]; $v = $matches[2]
                    if ($k -ne "Content-Type") { $headers[$k] = $v }
                }
            }

            # Body (--data, -d, --data-raw)
            if ($raw -match "(?:--data|--data-raw|-d)\s+(['`"])(.*?)\1") {
                $body = $matches[2]
                if ($method -eq "GET") { $method = "POST" }
            }

            # Apply to UI
            if ($url) { $script:textUrl.Text = $url }
            $script:comboMethod.SelectedItem = $method
            
            $headerText = ""
            foreach ($k in $headers.Keys) { $headerText += "${k}: $($headers[$k])`r`n" }
            $script:textHeaders.Text = $headerText
            
            $script:textBody.Text = $body
            if ($body.Trim().StartsWith("{") -or $body.Trim().StartsWith("[")) { $script:comboBodyType.SelectedItem = "application/json" }

            $curlForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $curlForm.Close()
        }
        $btnCancel = New-Button -Text "Cancel" -Property @{ Dock = "Right"; Width = 100 } -OnClick { $curlForm.Close() }
        
        $panelBtn.Controls.AddRange(@($btnCancel, $btnImport))
        $curlForm.Controls.AddRange(@($txtCurl, $labelCurl, $panelBtn))
        $curlForm.ShowDialog($form)
    })    
    $importCurlMenuItem.Visible = $script:settings.EnableCurlImport

    $importPostmanMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import Postman Collection...", $null, {
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Filter = "Postman Collection (*.json)|*.json"
            Title  = "Import Postman Collection"
        }
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $jsonContent = Get-Content -Path $openFileDialog.FileName -Raw | ConvertFrom-Json
                
                if (-not $jsonContent.info -or -not $jsonContent.item) {
                    throw "Invalid Postman Collection format. Only v2.1 is supported."
                }

                function Convert-PostmanItems {
                    param($Items)
                    $converted = @()
                    foreach ($item in $Items) {
                        if ($item.item) {
                            $folder = [PSCustomObject]@{
                                Name = $item.name
                                Type = "Folder"
                                Items = (Convert-PostmanItems -Items $item.item)
                            }
                            $converted += $folder
                        } elseif ($item.request) {
                            $req = $item.request
                            if ($req.url -is [string]) { $url = $req.url } elseif ($req.url.raw) { $url = $req.url.raw } else { $url = "" }
                            $method = $req.method
                            
                            $headers = ""
                            if ($req.header -is [array]) {
                                $headers = ($req.header | ForEach-Object { "$($_.key): $($_.value)" }) -join "`r`n"
                            }

                            $body = ""
                            $bodyType = "text/plain"
                            if ($req.body) {
                                if ($req.body.mode -eq "raw") {
                                    $body = $req.body.raw
                                    if ($req.body.options.raw.language -eq "json") { $bodyType = "application/json" }
                                    elseif ($req.body.options.raw.language -eq "xml") { $bodyType = "application/xml" }
                                } elseif ($req.body.mode -eq "formdata") {
                                    $bodyType = "multipart/form-data"
                                    $lines = @()
                                    foreach ($fd in $req.body.formdata) {
                                        if ($fd.type -eq "file") { $lines += "$($fd.key)=@`"$($fd.src)`"" }
                                        else { $lines += "$($fd.key)=$($fd.value)" }
                                    }
                                    $body = $lines -join "`r`n"
                                } elseif ($req.body.mode -eq "urlencoded") {
                                    $bodyType = "application/x-www-form-urlencoded"
                                    $pairs = @()
                                    foreach ($ue in $req.body.urlencoded) {
                                        $pairs += "$([uri]::EscapeDataString($ue.key))=$([uri]::EscapeDataString($ue.value))"
                                    }
                                    $body = $pairs -join "&"
                                }
                            }

                            $authData = @{ Type = "No Auth" }
                            if ($req.auth) {
                                if ($req.auth.type -eq "basic") {
                                    $u = ($req.auth.basic | Where-Object { $_.key -eq "username" }).value
                                    $p = ($req.auth.basic | Where-Object { $_.key -eq "password" }).value
                                    $authData = @{ Type = "Basic Auth"; Username = $u; Password = $p }
                                } elseif ($req.auth.type -eq "bearer") {
                                    $t = ($req.auth.bearer | Where-Object { $_.key -eq "token" }).value
                                    $authData = @{ Type = "Bearer Token"; Token = $t }
                                }
                            }

                            $converted += [PSCustomObject]@{ Name = $item.name; Type = "Request"; RequestData = [PSCustomObject]@{ Timestamp = Get-Date; Method = $method; Url = $url; Headers = $headers; Body = $body; BodyType = $bodyType; OutputFormat = ""; Tests = ""; PreRequestScript = ""; Authentication = $authData } }
                        }
                    }
                    return $converted
                }

                $importedItems = Convert-PostmanItems -Items $jsonContent.item
                $script:collections += [PSCustomObject]@{ Name = $jsonContent.info.name; Type = "Collection"; Items = $importedItems; Variables = @{} }
                Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                Save-Collections
                [System.Windows.Forms.MessageBox]::Show("Postman collection imported successfully.", "Import Complete", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to import Postman collection: $($_.Exception.Message)", "Import Error", "OK", "Error")
            }
        }
    })
    $importPostmanMenuItem.Visible = $script:settings.EnablePostmanImport

    $importWorkspaceMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import Workspace...", $null, {
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Filter = "API Tester Workspace (*.apw)|*.apw"
            Title  = "Import Workspace"
            InitialDirectory = $configDir
        }
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $workspace = Get-Content -Path $openFileDialog.FileName -Raw | ConvertFrom-Json
                if ($workspace.PSObject.Properties.Name -contains 'Settings') { #FIX: Corrected condition
                    # Create an import options form
                    $importOptionsForm = New-Object System.Windows.Forms.Form -Property @{
                        Text = "Import Options" #FIX: Corrected form size
                        Size = New-Object System.Drawing.Size(320, 260)
                        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
                        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                        MaximizeBox = $false; MinimizeBox = $false
                    }
                    $labelInfo = New-Label -Text "Select components to import from workspace." -Location (New-Object System.Drawing.Point(15, 15)) -Size (New-Object System.Drawing.Size(280, 20))
                    $checkImportEnvironments = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import Environments"; Location = (New-Object System.Drawing.Point(18, 45)); AutoSize = $true }
                    $checkImportGlobals = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import Globals"; Location = (New-Object System.Drawing.Point(18, 105)); AutoSize = $true }
                    $checkImportCollections = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import Collections"; Location = (New-Object System.Drawing.Point(18, 135)); AutoSize = $true }

                    # Enable/disable checkboxes based on what's in the file
                    $checkImportEnvironments.Enabled = $workspace.PSObject.Properties.Name -contains 'Environments'
                    $checkImportHistory.Enabled = $workspace.PSObject.Properties.Name -contains 'History'
                    $checkImportGlobals.Enabled = $workspace.PSObject.Properties.Name -contains 'Globals'
                    $checkImportCollections.Enabled = $workspace.PSObject.Properties.Name -contains 'Collections'
                    $checkImportEnvironments.Checked = $checkImportEnvironments.Enabled
                    $checkImportHistory.Checked = $checkImportHistory.Enabled
                    $checkImportGlobals.Checked = $checkImportGlobals.Enabled
                    $checkImportCollections.Checked = $checkImportCollections.Enabled

                    $btnContinueImport = New-Button -Text "Import" -Location (New-Object System.Drawing.Point(190, 180)) -Size (New-Object System.Drawing.Size(100, 30)) -OnClick {
                        # Always import settings
                        $workspace.Settings | ConvertTo-Json -Depth 5 | Set-Content -Path $settingsFilePath
                        Write-Log "Imported Settings from workspace." -Level Debug

                        if ($checkImportEnvironments.Checked) {
                            $workspace.Environments | ConvertTo-Json -Depth 5 | Set-Content -Path $environmentsFilePath -ErrorAction Stop
                            Write-Log "Imported Environments from workspace." -Level Debug
                        }
                        if ($checkImportHistory.Checked) {
                            $workspace.History | ConvertTo-Json -Depth 5 | Set-Content -Path $historyFilePath -ErrorAction Stop
                            Write-Log "Imported History from workspace." -Level Debug
                        }
                        if ($checkImportGlobals.Checked) {
                            $workspace.Globals | ConvertTo-Json -Depth 5 | Set-Content -Path $globalsFilePath -ErrorAction Stop
                            Write-Log "Imported Globals from workspace." -Level Debug
                        }
                        if ($checkImportCollections.Checked) {
                            $workspace.Collections | ConvertTo-Json -Depth 10 | Set-Content -Path $collectionsFilePath -ErrorAction Stop
                            Write-Log "Imported Collections from workspace." -Level Debug
                        }

                        # Reload everything into the current session
                        Write-Log "Workspace import complete. Reloading UI."
                        Load-Settings
                        Load-Globals
                        Load-Environments
                        Load-Collections
                        if ($script:settings.EnableHistory) { Load-History }
                        Populate-EnvironmentDropdown
                        Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                        $script:activeCollectionNode = $null
                        $script:activeCollectionVariables = @{}
                        Update-Layout
                        Populate-HistoryList
                        [System.Windows.Forms.MessageBox]::Show("Workspace components successfully imported. The application will now reflect the changes.", "Import Successful", "OK", "Information")
                        $importOptionsForm.Close()
                    }
                    $btnCancelImport = New-Button -Text "Cancel" -Location (New-Object System.Drawing.Point(80, 180)) -Size (New-Object System.Drawing.Size(100, 30)) -OnClick { $importOptionsForm.Close() }
                    
                    $importOptionsForm.Controls.AddRange(@($labelInfo, $checkImportEnvironments, $checkImportHistory, $checkImportGlobals, $checkImportCollections, $btnContinueImport, $btnCancelImport))
                    $importOptionsForm.ShowDialog($form)
                } else {
                    [System.Windows.Forms.MessageBox]::Show("The selected file is not a valid workspace file.", "Import Error", "OK", "Error")
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to import workspace: $($_.Exception.Message)", "Import Error", "OK", "Error")
                Write-Log "Error importing workspace file '$($openFileDialog.FileName)': $($_.Exception.Message)" -Level Info
            }
        }
    })
    $exportWorkspaceMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Export Workspace...", $null, {
        # Create a small form to ask about including history
        $exportOptionsForm = New-Object System.Windows.Forms.Form -Property @{
            Text = "Export Options"
            Size = New-Object System.Drawing.Size(450, 340) # Increased height for better button spacing
            StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
            FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
            MaximizeBox = $false
            MinimizeBox = $false
        }
        $labelInfo = New-Label -Text "Select options for your workspace export." -Location (New-Object System.Drawing.Point(15, 15)) -Size (New-Object System.Drawing.Size(410, 25))
        $checkIncludeEnvironments = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include environments in export"
            Location = New-Object System.Drawing.Point(18, 50)
            AutoSize = $true
        }
        $checkIncludeHistory = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include request history in export"
            Location = New-Object System.Drawing.Point(18, 85) # Moved down
            AutoSize = $true
        }
        $checkIncludeGlobals = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include global variables in export"
            Location = New-Object System.Drawing.Point(18, 120)
            AutoSize = $true
        }
        $checkIncludeCollections = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include collections in export"
            Location = New-Object System.Drawing.Point(18, 155)
            AutoSize = $true
        }
        # Disable checkboxes if there is no data to export
        $checkIncludeEnvironments.Enabled = ($null -ne $script:environments -and $script:environments.Count -gt 0)
        $checkIncludeHistory.Enabled = ($null -ne $script:history -and $script:history.Count -gt 0)
        $checkIncludeGlobals.Enabled = ($null -ne $script:globals -and $script:globals.Count -gt 0)
        $checkIncludeCollections.Enabled = ($null -ne $script:collections -and $script:collections.Count -gt 0)
        $checkIncludeEnvironments.Checked = $checkIncludeEnvironments.Enabled
        $checkIncludeHistory.Checked = $checkIncludeHistory.Enabled
        $checkIncludeGlobals.Checked = $checkIncludeGlobals.Enabled
        $checkIncludeCollections.Checked = $checkIncludeCollections.Enabled

        $btnContinueExport = New-Button -Text "Export..." -Location (New-Object System.Drawing.Point(310, 300)) -Size (New-Object System.Drawing.Size(110, 40)) -OnClick {
            $exportOptionsForm.Close() # Close the options form first
            $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog -Property @{
                Filter = "API Tester Workspace (*.apw)|*.apw"
                DefaultExt = "apw"
                FileName = "api_tester_workspace.apw"
                Title = "Export Workspace"
                InitialDirectory = $configDir
            }
            if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $workspace = [PSCustomObject]@{
                    # Settings are always included in a workspace export.
                    Settings = $script:settings
                }
                if ($checkIncludeEnvironments.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "Environments" -Value $script:environments
                }
                if ($checkIncludeHistory.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "History" -Value $script:history
                }
                if ($checkIncludeGlobals.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "Globals" -Value $script:globals
                }
                if ($checkIncludeCollections.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "Collections" -Value $script:collections
                }
                try {
                    $workspace | ConvertTo-Json -Depth 10 | Set-Content -Path $saveFileDialog.FileName -ErrorAction Stop
                    [System.Windows.Forms.MessageBox]::Show("Workspace successfully exported.", "Export Complete", "OK", "Information")
                } catch {
                    Write-Log "Error exporting workspace: $($_.Exception.Message)" -Level Info
                    [System.Windows.Forms.MessageBox]::Show("Failed to export workspace: $($_.Exception.Message)", "Export Error", "OK", "Error")
                }
            }
        }
        $btnCancelExport = New-Button -Text "Cancel" -Location (New-Object System.Drawing.Point(200, 300)) -Size (New-Object System.Drawing.Size(100, 40)) -OnClick {
            $exportOptionsForm.Close()
        }
        $exportOptionsForm.Controls.AddRange(@($labelInfo, $checkIncludeEnvironments, $checkIncludeHistory, $checkIncludeGlobals, $checkIncludeCollections, $btnContinueExport, $btnCancelExport))
        $exportOptionsForm.ShowDialog($form)
    })

    $settingsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Settings...", $null, { 
        # Directly call the function to show the settings window.
        $result = Show-SettingsWindow -parentForm $form

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Log "Settings saved and applied."
            Update-Layout
            $importCurlMenuItem.Visible = $script:settings.EnableCurlImport
            $importPostmanMenuItem.Visible = $script:settings.EnablePostmanImport

            # Update Console Welcome Message if it is currently displayed (and no other history exists)
            if ($script:consoleOutput -and $script:consoleOutput.Text -match "(?s)^Welcome to API Tester Console.*?Example: python: print\('Hello'\)\s+$") {
                $defaultLang = if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { "PowerShell" }
                $script:consoleOutput.Text = "Welcome to API Tester Console.`nDefault language: $defaultLang.`nPrefix commands with 'python:', 'js:', 'php:', 'ruby:', 'go:', 'bat:', 'bash:' to switch languages.`nExample: python: print('Hello')`n`n"
            }
        } else {
            Write-Log "Settings dialog cancelled."
        }
    })
    
    $exitMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit", $null, { $form.Close() })

    $resetLayoutMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Layout", $null, {
        $script:responseDockState = 'Right'
        $script:settings.ResponseDockState = 'Right'
        $script:isHistoryUndocked = $false
        # Calculate optimal splitter distances based on form width
        $formWidth = $form.ClientSize.Width
        $splitContainer.SplitterDistance = [int]($formWidth * 0.7)  # 70% for Body+Response, 30% for History
        $mainContentSplitter.SplitterDistance = [int](($formWidth * 0.7) * 0.45)  # 45% of left panel for Body, 55% for Response
        Save-Settings
        Update-Layout
        [System.Windows.Forms.MessageBox]::Show("Layout has been reset to defaults.", "Reset Layout", "OK", "Information")
    })

    $fileMenu.DropDownItems.AddRange(@(
        $importCurlMenuItem, $importPostmanMenuItem, $importWorkspaceMenuItem, $exportWorkspaceMenuItem, 
        (New-Object System.Windows.Forms.ToolStripSeparator), 
        $resetLayoutMenuItem,
        $settingsMenuItem, 
        (New-Object System.Windows.Forms.ToolStripSeparator), 
        $exitMenuItem
    ))
    $menuStrip.Items.Add($fileMenu)

    $globalVarsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Global Variables...", $null, {
        $result = Show-VariablesEditor -parentForm $form -Title "Global Variables" -Variables $script:globals
        if ($result.Result -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:globals = if ($result.Variables) { $result.Variables } else { @{} }
            Save-Globals
            Write-Log "Global variables updated."
        }
    })
    $toolsMenu.DropDownItems.Add($globalVarsMenuItem)
    $toolsMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))

    $proxyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Proxy Configuration...", $null, { Show-ProxySettings -parentForm $form })
    $toolsMenu.DropDownItems.Add($proxyMenuItem)

    $cookieJarMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Cookie Jar...", $null, { Show-CookieJar -parentForm $form })
    $toolsMenu.DropDownItems.Add($cookieJarMenuItem)

    $jwtMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("JWT Utility...", $null, { Show-JwtTool })
    $toolsMenu.DropDownItems.Add($jwtMenuItem)

    $reportMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Generate Report...", $null, { Show-ReportGenerator -parentForm $form })
    $toolsMenu.DropDownItems.Add($reportMenuItem)

    $wsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("WebSocket Client...", $null, { Show-WebSocketClient -parentForm $form })
    $toolsMenu.DropDownItems.Add($wsMenuItem)

    $grpcMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("gRPC Client...", $null, { Show-GrpcClient -parentForm $form })
    $toolsMenu.DropDownItems.Add($grpcMenuItem)

    $menuStrip.Items.Add($toolsMenu)

    $monitorManagerItem = New-Object System.Windows.Forms.ToolStripMenuItem("Monitor Manager...", $null, { Show-MonitorManager -parentForm $form })
    $monitorDashboardItem = New-Object System.Windows.Forms.ToolStripMenuItem("Monitoring Dashboard...", $null, { Show-MonitoringDashboard -parentForm $form })

    $monitorMenu.DropDownItems.AddRange(@($monitorManagerItem, $monitorDashboardItem))
    $menuStrip.Items.Add($monitorMenu)

    # --- Help Menu ---
    $helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Help")
    $aboutMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("About PowerShell API Tester...", $null, {
        Show-AboutDialog -parentForm $form
    })
    $shortcutsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Keyboard Shortcuts...", $null, {
        Show-KeyboardShortcuts -parentForm $form
    })
    $helpMenu.DropDownItems.AddRange(@($aboutMenuItem, $shortcutsMenuItem))
    $menuStrip.Items.Add($helpMenu)

    $form.MainMenuStrip = $menuStrip

    # GroupBox for selecting the active environment.
    $groupEnvironment = New-Object System.Windows.Forms.GroupBox -Property @{
        Height   = 110
        Dock     = 'Top'
        Text     = "Environment"
        Padding  = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }
    # Use TableLayoutPanel for perfect alignment and to prevent cutoff
    $panelEnvInner = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ 
        Dock = 'Fill'
        ColumnCount = 3
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 10, 5, 5)
    }
    $panelEnvInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelEnvInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelEnvInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelEnvInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 35)))

    $labelEnvironment = New-Label -Text "Active Environment:" -Property @{ 
        AutoSize = $true
        Anchor = 'Left, Right'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(0, 5, 10, 0)
    }

    $script:comboEnvironment = New-Object System.Windows.Forms.ComboBox -Property @{
        Name          = 'comboEnvironment'
        Anchor        = 'Left, Right'
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        Height        = 28
        Margin        = [System.Windows.Forms.Padding]::new(0, 3, 0, 0)
    }

    $btnManageEnvs = New-Button -Text "Manage..." -OnClick {
        Show-EnvironmentManagerWindow -parentForm $form
        Populate-EnvironmentDropdown
    } -Property @{
        Width = 100
        Height = 35
        Anchor = 'Right'
        Margin = [System.Windows.Forms.Padding]::new(10, 3, 0, 0)
    }

    $panelEnvInner.Controls.Add($labelEnvironment, 0, 0)
    $panelEnvInner.Controls.Add($script:comboEnvironment, 1, 0)
    $panelEnvInner.Controls.Add($btnManageEnvs, 2, 0)

    $groupEnvironment.Controls.Add($panelEnvInner)

    # Populates the environment dropdown, preserving the current selection if possible.
    function Populate-EnvironmentDropdown {
        $currentSelection = $script:comboEnvironment.SelectedItem
        $script:comboEnvironment.Items.Clear()
        $script:comboEnvironment.Items.Add("No Environment") # Always include this option
        $script:environments.Keys | Sort-Object | ForEach-Object { $script:comboEnvironment.Items.Add($_) }
        if ($currentSelection -and $script:comboEnvironment.Items.Contains($currentSelection)) { $script:comboEnvironment.SelectedItem = $currentSelection } else { $script:comboEnvironment.SelectedItem = "No Environment" }
    }

    # When an environment is selected, populate the main form's fields.
    $script:comboEnvironment.Add_SelectedIndexChanged({
        $selectedEnvName = $script:comboEnvironment.SelectedItem
        if ($selectedEnvName -ne "No Environment" -and $script:environments.ContainsKey($selectedEnvName)) {
            $script:settings.LastActiveEnvironment = $selectedEnvName
            if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Environment" -and $null -ne $updateExtractVarList) {
                & $updateExtractVarList
            }
            Save-Settings

            $envData = $script:environments[$selectedEnvName] # Retrieve the environment data

            # Populate URL and Headers
            $script:textUrl.Text = $envData.Url
            $script:textHeaders.Text = $envData.Headers

            # Populate Authentication
            if ($envData.Authentication) {
                $auth = $envData.Authentication
                $script:authPanel.ComboAuthType.SelectedItem = $auth.Type
                & $script:authPanel.SwitchPanel # Update the visible auth panel
                switch ($auth.Type) {
                    "API Key"      { $script:authPanel.TextApiKeyName.Text = $auth.Key; $script:authPanel.TextApiKeyValue.Text = $auth.Value; $script:authPanel.ComboApiKeyAddTo.SelectedItem = $auth.AddTo }
                    "Bearer Token" { $script:authPanel.TextBearerToken.Text = $auth.Token }
                    "Basic Auth"   { $script:authPanel.TextBasicUser.Text = $auth.Username; $script:authPanel.TextBasicPass.Text = $auth.Password }
                    "Auth2"        {
                        $script:authPanel.TextAuth2ClientId.Text = $auth.ClientId
                        $script:authPanel.TextAuth2ClientSecret.Text = $auth.ClientSecret
                        $script:authPanel.TextAuth2AuthEndpoint.Text = $auth.AuthEndpoint
                        $script:authPanel.TextAuth2RedirectUri.Text = $auth.RedirectUri
                        $script:authPanel.TextAuth2TokenEndpoint.Text = $auth.TokenEndpoint
                        $script:authPanel.TextAuth2Scope.Text = $auth.Scope
                        $script:authPanel.TextAuth2AccessToken.Text = $auth.AccessToken
                        $script:authPanel.TextAuth2RefreshToken.Text = $auth.RefreshToken
                        $script:authPanel.TextAuth2ExpiresIn.Text = $auth.ExpiresIn
                        $script:authPanel.TextAuth2AccessToken.Tag = $auth.TokenExpiryTimestamp
                    }
                    "Client Certificate" {
                        $script:authPanel.ComboCertSource.SelectedItem = $auth.Source
                        $script:authPanel.TextCertPath.Text = $auth.Path
                        $script:authPanel.TextCertPass.Text = $auth.Password
                        $script:authPanel.TextCertThumb.Text = $auth.Thumbprint
                    }
                }
            }
            Write-Log "Applied environment '$selectedEnvName' to the current request." -Level Info
        }
        if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Environment" -and $null -ne $updateExtractVarList) {
            & $updateExtractVarList
        }
    })

    $form.Add_Resize({
        if ($script:isMainFormClosing -or $form.IsDisposed) { return }
        $form.SuspendLayout()
        Update-Layout
        $form.ResumeLayout()
    })

    # Main layout container, splitting the request/response view from the history panel.
    $splitContainer = New-Object System.Windows.Forms.SplitContainer -Property @{ # This is the main splitter for Request/Response vs History
        Name             = 'splitContainer'
        Dock             = [System.Windows.Forms.DockStyle]::Fill
        BorderStyle      = [System.Windows.Forms.BorderStyle]::FixedSingle
        SplitterDistance = 590 # Initial width of the left panel (request/response)
    }

    # This splitter is for handling Left/Right docking of the Response panel
    $mainContentSplitter = New-Object System.Windows.Forms.SplitContainer -Property @{
        Name        = 'mainContentSplitter'
        Dock        = [System.Windows.Forms.DockStyle]::Fill
        Orientation = [System.Windows.Forms.Orientation]::Vertical
        BorderStyle = [System.Windows.Forms.BorderStyle]::None # No double border
        SplitterDistance = 590
    }
    # This panel will hold the Request and Output controls when the Response is side-docked
    $mainContentPanel = New-Object System.Windows.Forms.Panel -Property @{
        Name = 'mainContentPanel'
        Dock = [System.Windows.Forms.DockStyle]::Fill
        Padding = [System.Windows.Forms.Padding]::new(10)
    }

    # Add the new splitter to the original split container's Panel1
    $splitContainer.Panel1.Controls.Add($mainContentSplitter)
    
    # GroupBox for manual output file settings and the main Send/Cancel buttons.
    $groupOutput = New-Object System.Windows.Forms.GroupBox -Property @{
        Height   = 180
        Dock     = 'Top'
        Text     = "Output & Submission"
        Padding  = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }

    # Refactored: Use Panels with Docking strategy consistent with Request/Environment panels
    $panelOutputFormat = New-Object System.Windows.Forms.Panel -Property @{
        Dock = 'Top'
        Height = 50
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
    }
    $labelOutputFormat = New-Label -Text "Output Format:" -Property @{ 
        Dock = 'Left'
        AutoSize = $false
        Width = 160
        TextAlign = 'MiddleLeft'
    }
    $script:textOutputFormat = New-TextBox -Multiline $false -Property @{
        Name = 'textOutputFormat'
        Dock = 'Fill'
    }
    $toolTip.SetToolTip($script:textOutputFormat, "Specify a form field such as outputFormat=TrackChanges.")
    $panelOutputFormat.Controls.AddRange(@($script:textOutputFormat, $labelOutputFormat))

    $panelOutputFile = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Top'
        Height = 36
        ColumnCount = 3
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 0, 5, 0)
    }
    $panelOutputFile.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 160)))
    $panelOutputFile.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelOutputFile.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelOutputFile.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $labelOutputFile = New-Label -Text "Output File:" -Property @{ 
        Anchor = 'Left, Right'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(0, 3, 5, 0)
    }
    $script:textOutputFile = New-TextBox -Multiline $false -Property @{
        Anchor = 'Left, Right'
        Margin = [System.Windows.Forms.Padding]::new(0, 3, 0, 0)
    }
    $btnBrowseOutputFile = New-Button -Text "Browse..." -Property @{
        Anchor = 'Left'
        Height = 24
        Width = 100
        Margin = [System.Windows.Forms.Padding]::new(5, 3, 0, 0)
    } -OnClick {
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "All files (*.*)|*.*"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:textOutputFile.Text = $saveFileDialog.FileName
        }
    }

    $panelOutputFile.Controls.Add($labelOutputFile, 0, 0)
    $panelOutputFile.Controls.Add($script:textOutputFile, 1, 0)
    $panelOutputFile.Controls.Add($btnBrowseOutputFile, 2, 0)

    $panelOutputActions = New-Object System.Windows.Forms.Panel -Property @{
        Dock = 'Bottom'
        Height = 60
        Padding = [System.Windows.Forms.Padding]::new(5, 10, 5, 5)
    }

    $groupOutput.Controls.AddRange(@($panelOutputActions, $panelOutputFile, $panelOutputFormat))
    $panelOutputActions.BringToFront()
    $panelOutputFile.BringToFront()
    $panelOutputFormat.BringToFront()

    # Updates UI elements based on current settings, such as toggling control visibility.
    function Update-UI-Mode {
        $showOutputFileControls = -not $script:settings.AutoSaveToFile
        
        $labelOutputFile.Visible = $showOutputFileControls
        $script:textOutputFile.Visible = $showOutputFileControls
        $btnBrowseOutputFile.Visible = $showOutputFileControls
        # OutputFormat controls are always visible, so no need to toggle here.

        if (-not $showOutputFileControls) { $script:textOutputFile.Text = "" }

        if ($script:settings.EnableAllMethods) {
            $script:comboMethod.Enabled = $true
        } else {
            $script:comboMethod.Enabled = $false
            $script:comboMethod.SelectedItem = "POST"
        }

        # Show/Hide Repeat button based on settings
        $btnRepeat.Visible = $script:settings.EnableRepeatRequest
    }

    # Creates the separate, undockable window for the request history panel.
    function New-HistoryWindow {
        if ($script:historyForm -and -not $script:historyForm.IsDisposed) { return } # Don't create if it already exists and is not disposed

        $script:historyForm = New-Object System.Windows.Forms.Form -Property @{ # Initialize the form
            Text          = "History"
            Size          = New-Object System.Drawing.Size(300, 600)
            StartPosition = [System.Windows.Forms.FormStartPosition]::WindowsDefaultLocation # Start with a default location
            FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
            ShowInTaskbar = $false
            Owner         = $form
        }

        $historyFormShownHandler = {
            # Position the history window next to the main form, then remove this event handler.
            $script:historyForm.Location = New-Object System.Drawing.Point(([int]$form.Location.X + [int]$form.Width), [int]$form.Location.Y)
            $script:historyForm.Remove_Shown($historyFormShownHandler)
        }
        $script:historyForm.Add_Shown($historyFormShownHandler)

        # Handle the 'X' button click: hide the window and re-dock the panel instead of closing.
        $script:historyForm.Add_FormClosing({
            param($sender, $e)
            $isAppShutdown = $script:isMainFormClosing -or ($e.CloseReason -in @(
                [System.Windows.Forms.CloseReason]::FormOwnerClosing,
                [System.Windows.Forms.CloseReason]::ApplicationExitCall,
                [System.Windows.Forms.CloseReason]::TaskManagerClosing,
                [System.Windows.Forms.CloseReason]::WindowsShutDown
            ))

            if (-not $isAppShutdown) { # Only re-dock if main form is not closing
                $e.Cancel = $true # Prevent the form from being disposed.
                $script:isHistoryUndocked = $false
                Update-Layout # Re-dock the panel.
                Write-Log "Undocked history window closed, re-docking." -Level Debug
            } else {
                Write-Log "Undocked history window closing due to main form closure." -Level Debug
            }
        })
        Write-Log "Created undocked history window."
    }

    # Creates the separate, undockable window for the response panel.
    function New-ResponseWindow {
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) { return } # Don't create if it already exists
        Write-Log "Creating undocked response window." -Level Debug


        $script:responseForm = New-Object System.Windows.Forms.Form -Property @{
            Text          = "Response"
            Size          = New-Object System.Drawing.Size(600, 700)
            StartPosition = [System.Windows.Forms.FormStartPosition]::WindowsDefaultLocation
            FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
            ShowInTaskbar = $true # Show in taskbar as it's a primary content window
            Owner         = $form
            MaximizeBox   = $true
            MinimizeBox   = $true
        }

        # Handle the 'X' button click: hide the window and re-dock the panel.
        $script:responseForm.Add_FormClosing({
            param($sender, $e)
            $isAppShutdown = $script:isMainFormClosing -or ($e.CloseReason -in @(
                [System.Windows.Forms.CloseReason]::FormOwnerClosing,
                [System.Windows.Forms.CloseReason]::ApplicationExitCall,
                [System.Windows.Forms.CloseReason]::TaskManagerClosing,
                [System.Windows.Forms.CloseReason]::WindowsShutDown
            ))

            if (-not $isAppShutdown) { # Only re-dock if main form is not closing
                $e.Cancel = $true # Prevent the form from being disposed.
                $script:responseDockState = 'Bottom' # Default back to bottom docking
                # Use the last known dock state instead of defaulting to Bottom
                & $setDockState $script:lastDockState
                Write-Log "Undocked response window closed, re-docking." -Level Debug
            } else {
                Write-Log "Undocked response window closing due to main form closure." -Level Debug
            }
        })
        Write-Log "Undocked response window created." -Level Debug
    }


    # Recalculates and applies the positions and sizes of all major UI panels.
    # This function is called on form resize and when settings change.
    function Update-Layout {
        if (-not $tabRequestBody) { return } # Guard clause to prevent execution before UI tabs are initialized
        if ($script:isMainFormClosing) { return }
        # Suspend layout logic to prevent flickering during updates
        $form.SuspendLayout()
        $mainContentSplitter.SuspendLayout()
        Update-UI-Mode

        # Update checkmarks on the docking context menu
        $dockBottomMenuItem.Checked = ($script:responseDockState -eq 'Bottom')
        $dockLeftMenuItem.Checked = ($script:responseDockState -eq 'Left')
        $dockRightMenuItem.Checked = ($script:responseDockState -eq 'Right')
        $undockMenuItem.Checked = ($script:responseDockState -eq 'Undocked')

        if ($script:isHistoryUndocked -and $script:settings.EnableHistory) {
            $splitContainer.Panel2Collapsed = $true
            
            if (-not $script:historyForm -or $script:historyForm.IsDisposed) {
                New-HistoryWindow # This will create/recreate $script:historyForm
            }
            if (-not $script:historyForm.Controls.Contains($groupHistory)) {
                $groupHistory.Parent = $script:historyForm
            }
            if (-not $script:historyForm.Visible) {
                $script:historyForm.Show($form) # Show() will make it visible.
            }
        } else {
            if ($script:historyForm -and -not $script:historyForm.IsDisposed -and $script:historyForm.Visible) { $script:historyForm.Hide() }
            if (-not $splitContainer.Panel2.Controls.Contains($groupHistory)) {
                $groupHistory.Parent = $splitContainer.Panel2
            }
            $splitContainer.Panel2Collapsed = (-not $script:settings.ShowHistory) -or (-not $script:settings.EnableHistory)
        }

        # 1. Detach groupResponse and mainContentPanel from any parent, and clear splitter panels.
        $groupResponse.Parent = $null # Detach groupResponse from any parent
        $mainContentPanel.Parent = $null # Detach mainContentPanel from any parent
        $mainContentSplitter.Panel1.Controls.Clear()
        $mainContentSplitter.Panel2.Controls.Clear()
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) { $script:responseForm.Controls.Clear() }

        if ($script:responseDockState -eq 'Undocked') {
            $groupResponse.Dock = 'Fill' # Make it fill the new window
            if (-not $script:responseForm -or $script:responseForm.IsDisposed) {
                New-ResponseWindow
            }
            if (-not $script:responseForm.Controls.Contains($groupResponse)) {
                $groupResponse.Parent = $script:responseForm
            }
            if (-not $script:responseForm.Visible) { $script:responseForm.Show() }
            $mainContentSplitter.Panel2Collapsed = $true
            $mainContentSplitter.Panel1.Controls.Add($mainContentPanel) # mainContentPanel gets request/output
            $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Top
            $mainContentPanel.Controls.AddRange(@($groupEnvironment, $groupRequest, $groupOutput))
            $groupResponse.Visible = $true
        } elseif ($script:responseDockState -eq 'Left' -or $script:responseDockState -eq 'Right') {
            if ($script:responseForm -and -not $script:responseForm.IsDisposed -and $script:responseForm.Visible) { $script:responseForm.Hide() }

            $mainContentSplitter.Panel2Collapsed = $false
            $groupResponse.Dock = 'Fill'
            $mainContentSplitter.Orientation = [System.Windows.Forms.Orientation]::Vertical # Use Vertical for a side-by-side split

            if ($script:responseDockState -eq 'Left') {
                $groupResponse.Parent = $mainContentSplitter.Panel1 # Reparent to splitter panel 1
                $mainContentPanel.Parent = $mainContentSplitter.Panel2 # Reparent mainContentPanel to splitter panel 2
                $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Left
                $mainContentSplitter.SplitterDistance = [int]($mainContentSplitter.ClientSize.Width * 0.4) # 40% for response
            } else { # Right
                $mainContentPanel.Parent = $mainContentSplitter.Panel1 # Reparent mainContentPanel to splitter panel 1
                $groupResponse.Parent = $mainContentSplitter.Panel2 # Reparent to splitter panel 2
                $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Right
                $mainContentSplitter.SplitterDistance = [int]($mainContentSplitter.ClientSize.Width * 0.6) # 60% for request/output
            }
            $mainContentPanel.Controls.AddRange(@($groupEnvironment, $groupRequest, $groupOutput))
            $groupResponse.Visible = $true
        } else {
            # Default 'Bottom' docking
            $groupResponse.Dock = 'Fill'
            if ($script:responseForm -and -not $script:responseForm.IsDisposed -and $script:responseForm.Visible) { $script:responseForm.Hide() }
            $mainContentSplitter.Orientation = [System.Windows.Forms.Orientation]::Vertical
            $mainContentSplitter.Panel1.Controls.Add($mainContentPanel) # mainContentPanel gets request/output
            $mainContentSplitter.Panel2Collapsed = $true
            $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Top
            
            $groupResponse.Parent = $mainContentPanel # Reparent to mainContentPanel
            $mainContentPanel.Controls.AddRange(@($groupEnvironment, $groupRequest, $groupOutput, $groupResponse))
            $groupResponse.Visible = $true
        } # End of Response Panel Docking State

        # Re-populate the request tabs based on visibility settings.
        $selectedRequestTab = $requestTabControl.SelectedTab
        $requestTabControl.TabPages.Clear()
        $requestTabControl.TabPages.Add($tabRequestBody)
        if ($script:settings.ShowRequestHeadersTab) { $requestTabControl.TabPages.Add($tabRequestHeaders) }
        if ($script:settings.ShowAuthTab) { $requestTabControl.TabPages.Add($tabAuth) }
        if ($script:settings.ShowPreRequestTab) { $requestTabControl.TabPages.Add($tabPreRequest) }
        if ($script:settings.ShowTestsTab) { $requestTabControl.TabPages.Add($tabRequestTests) }
        if ($selectedRequestTab -and $requestTabControl.TabPages.Contains($selectedRequestTab)) {
            $requestTabControl.SelectedTab = $selectedRequestTab
        }

        # Re-populate the response tabs based on visibility settings. This must be done
        # AFTER the parent control is set and visibility is determined.
        $selectedResponseTab = $tabControlResponse.SelectedTab
        $tabControlResponse.TabPages.Clear()
        # Only add tabs if the response group is visible in its current context
        # This ensures that if groupResponse.Visible is false, no tabs are added.
        if ($groupResponse.Visible) {
            if ($script:settings.ShowResponse) { $tabControlResponse.TabPages.Add($tabResponse) }
            if ($script:settings.ShowJsonTreeTab) { $tabControlResponse.TabPages.Add($tabJsonTree) }
            if ($script:settings.ShowResponseHeaders) { $tabControlResponse.TabPages.Add($tabHeaders) }
            if ($script:settings.ShowTestResultsTab) { $tabControlResponse.TabPages.Add($tabTestResults) }
            if ($script:settings.ShowCurl) { $tabControlResponse.TabPages.Add($tabCode) }
            if ($script:settings.ShowConsoleTab) { $tabControlResponse.TabPages.Add($tabConsole) }
        }
        # Restore the selected tab if it still exists
        if ($selectedResponseTab -and $tabControlResponse.TabPages.Contains($selectedResponseTab)) {
            $tabControlResponse.SelectedTab = $selectedResponseTab
        }

        # Determine if the entire response group box should be visible. This applies to its content.
        $isAnyResponseTabVisible = ($script:settings.ShowResponse -or 
                                    $script:settings.ShowResponseHeaders -or 
                                    $script:settings.ShowTestResultsTab -or 
                                    $script:settings.ShowCurl -or
                                    $script:settings.ShowConsoleTab)
        # If no tabs are visible, hide the groupResponse itself.
        if (-not $isAnyResponseTabVisible) { $groupResponse.Visible = $false }

        $groupEnvironment.Visible = $script:settings.ShowEnvironmentPanel

        # Apply Stacking Strategy
        $groupEnvironment.Dock = 'Top'
        $groupEnvironment.Height = 110

        if ($groupResponse.Visible -and ($script:responseDockState -eq 'Bottom')) {
            $groupRequest.Dock = 'Top'
            $groupRequest.Height = 500
            $groupOutput.Dock = 'Top'
            $groupOutput.Height = 180
            $groupResponse.Dock = 'Fill'
        } else {
            $groupOutput.Dock = 'Bottom'
            $groupOutput.Height = 180
            $groupRequest.Dock = 'Fill'
        }

        # Ensure correct visual order (Env -> Request -> Output -> Response)
        $groupEnvironment.BringToFront()
        
        if ($groupRequest.Dock -eq 'Top') {
            $groupRequest.BringToFront()
            $groupOutput.BringToFront()
            if ($groupResponse.Parent -eq $mainContentPanel) { $groupResponse.BringToFront() }
        } else {
            $groupOutput.BringToFront()
            $groupRequest.BringToFront()
        }
        
        # Update fonts
        if ($script:settings.ResponseFontSize -le 0) { $script:settings.ResponseFontSize = 9 }
        $responseFont = New-Object System.Drawing.Font("Courier New", $script:settings.ResponseFontSize)
        if ($richTextResponse) { $richTextResponse.Font = $responseFont }
        if ($richTextResponseHeaders) { $richTextResponseHeaders.Font = $responseFont }
        if ($richTextCode) { $richTextCode.Font = $responseFont }
        if ($script:richTextTestResults) { $script:richTextTestResults.Font = $responseFont }
        if ($script:consoleOutput) { $script:consoleOutput.Font = $responseFont; $script:consoleInput.Font = $responseFont }

        $mainContentSplitter.ResumeLayout()
        $form.ResumeLayout()
    }

    # --- GroupBox for Request Details ---
    $groupRequest = New-Object System.Windows.Forms.GroupBox -Property @{
        Height   = 500
        Dock     = 'Top'
        Text     = "Request"
        Padding  = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }

    # Use TableLayoutPanel for perfect alignment
    $panelRequestTabsTop = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Top'
        Height = 42
        ColumnCount = 5
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 0)
    }
    $panelRequestTabsTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelRequestTabsTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTabsTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTabsTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTabsTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTabsTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTabsTop.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $script:requestTabsStrip = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = 'Fill'
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)
    }

    $btnNewRequestTab = New-Button -Text "New Tab" -Style 'Secondary' -Property @{
        Width = 90
        Height = 30
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)
        Anchor = 'Right'
    }
    $btnDuplicateRequestTab = New-Button -Text "Duplicate" -Style 'Secondary' -OnClick {
        $activeState = Get-ActiveRequestTabState
        if ($activeState) {
            Add-RequestTab -InitialState $activeState
        }
    } -Property @{
        Width = 90
        Height = 30
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)
        Anchor = 'Right'
    }
    $btnCloseRequestTab = New-Button -Text "Close Tab" -Style 'Secondary' -OnClick {
        Remove-ActiveRequestTab
    } -Property @{
        Width = 90
        Height = 30
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)
        Anchor = 'Right'
    }
    $btnTemplates = New-Button -Text "Templates" -Style 'Secondary' -OnClick {
        Show-RequestTemplatesWindow
    } -Property @{
        Width = 95
        Height = 30
        Anchor = 'Right'
    }

    $panelRequestTabsTop.Controls.Add($script:requestTabsStrip, 0, 0)
    $panelRequestTabsTop.Controls.Add($btnTemplates, 4, 0)
    $panelRequestTabsTop.Controls.Add($btnCloseRequestTab, 3, 0)
    $panelRequestTabsTop.Controls.Add($btnDuplicateRequestTab, 2, 0)
    $panelRequestTabsTop.Controls.Add($btnNewRequestTab, 1, 0)

    $panelRequestTop = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Top'
        Height = 60
        ColumnCount = 4
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
    }
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelRequestTop.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $labelMethod = New-Label -Text "Method:" -Property @{ 
        AutoSize = $true
        Anchor = 'Left'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(5, 5, 10, 0)
    }

    $script:comboMethod = New-Object System.Windows.Forms.ComboBox -Property @{
        Name          = 'comboMethod'
        Width         = 100
        Anchor        = 'Left, Right'
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        Margin        = [System.Windows.Forms.Padding]::new(0, 0, 10, 0)
    }
    $script:comboMethod.Items.AddRange(@("POST", "GET", "PUT", "DELETE", "PATCH"))
    $script:comboMethod.SelectedIndex = 0

    $labelUrl = New-Label -Text "URL:" -Property @{ 
        AutoSize = $true
        Anchor = 'Left'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(0, 5, 10, 0)
    }

    $script:textUrl = New-TextBox -Multiline $false -Property @{
        Name     = 'textUrl'
        Anchor   = 'Left, Right'
    }

    $panelRequestTop.Controls.Add($labelMethod, 0, 0)
    $panelRequestTop.Controls.Add($script:comboMethod, 1, 0)
    $panelRequestTop.Controls.Add($labelUrl, 2, 0)
    $panelRequestTop.Controls.Add($script:textUrl, 3, 0)

    # --- NEW: TabControl for Body, Headers, Auth ---
    # --- TabControl for Body, Headers, Auth ---
    $requestTabControl = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = 'Fill'
        Margin = [System.Windows.Forms.Padding]::new(0, 10, 0, 0)
    }

    $tabRequestBody = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Body"; BorderStyle = 'None' }

    $bodyTopPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true}

    # Body Type Selection
    $labelBodyType = New-Label -Text "Body Type:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 0) }
    $script:comboBodyType = New-Object System.Windows.Forms.ComboBox -Property @{
        Name          = 'comboBodyType'
        Width         = 160
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    }
    $script:comboBodyType.Items.AddRange(@("multipart/form-data", "application/json", "application/xml", "text/plain", "application/x-www-form-urlencoded", "GraphQL"))
    $script:comboBodyType.SelectedIndex = 0 # Default to form-data

    $checkIncludeFilename = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include 'filename'"; AutoSize = $true; Checked = $script:settings.IncludeFilename; Margin = [System.Windows.Forms.Padding]::new(10, 3, 0, 0) }
    $toolTip.SetToolTip($checkIncludeFilename, "If checked, includes the 'filename' attribute in the multipart request part, which is standard for file uploads.")

    $checkIncludeContentType = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include 'type'"; AutoSize = $true; Checked = $script:settings.IncludeContentType; Margin = [System.Windows.Forms.Padding]::new(10, 3, 0, 0) }
    $toolTip.SetToolTip($checkIncludeContentType, "If checked, automatically determines and includes the Content-Type for the file part (e.g., 'application/pdf').")
    
    $bodyTopPanel.Controls.AddRange(@($labelBodyType, $script:comboBodyType, $checkIncludeFilename, $checkIncludeContentType))

    $panelBodyLabel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Top'; Height = 35; Padding = [System.Windows.Forms.Padding]::new(5, 0, 5, 0) }

    $labelBody = New-Label -Text "Body (key=value per line. Press 'Alt + @' to add a file):" -Property @{ Dock = 'Fill'; TextAlign = 'MiddleLeft' }
    
    $panelBodyLabel.Controls.Add($labelBody)

    $script:textBody = New-TextBox -Multiline $true -Property @{
        Name       = 'textBody'
        Dock       = 'Fill'
        ScrollBars = "Both"
        BorderStyle = 'None'
    }

    $script:panelMultipart = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; Visible = $false }
    $multipartToolbar = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Top'
        Height = 40
        FlowDirection = 'LeftToRight'
        Padding = [System.Windows.Forms.Padding]::new(0, 5, 0, 0)
    }
    $btnAddMultipartField = New-Button -Text "Add Field" -Style 'Secondary' -Property @{ Width = 100; Height = 28; Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0) }
    $btnAddMultipartFile = New-Button -Text "Add File" -Style 'Secondary' -Property @{ Width = 100; Height = 28; Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0) }
    $btnRemoveMultipartRow = New-Button -Text "Remove" -Style 'Secondary' -Property @{ Width = 90; Height = 28 }
    $multipartToolbar.Controls.AddRange(@($btnAddMultipartField, $btnAddMultipartFile, $btnRemoveMultipartRow))

    $script:gridMultipart = New-Object System.Windows.Forms.DataGridView -Property @{
        Dock = 'Fill'
        AllowUserToAddRows = $false
        AllowUserToDeleteRows = $false
        AutoSizeColumnsMode = 'Fill'
        RowHeadersVisible = $false
        BackgroundColor = $script:Theme.GroupBackground
        BorderStyle = 'None'
        SelectionMode = 'FullRowSelect'
        EditMode = 'EditOnEnter'
    }
    [void]$script:gridMultipart.Columns.Add("Key", "Key")
    $kindColumn = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
    $kindColumn.Name = "Kind"
    $kindColumn.HeaderText = "Type"
    [void]$kindColumn.Items.AddRange(@("Value", "File"))
    [void]$script:gridMultipart.Columns.Add($kindColumn)
    [void]$script:gridMultipart.Columns.Add("Value", "Value / File Path")
    [void]$script:gridMultipart.Columns.Add("FileName", "File Name")
    [void]$script:gridMultipart.Columns.Add("ContentType", "Content Type")
    $script:gridMultipart.Columns["Kind"].FillWeight = 55
    $script:gridMultipart.Columns["Key"].FillWeight = 90
    $script:gridMultipart.Columns["Value"].FillWeight = 180
    $script:gridMultipart.Columns["FileName"].FillWeight = 100
    $script:gridMultipart.Columns["ContentType"].FillWeight = 120
    $script:panelMultipart.Controls.Add($script:gridMultipart)
    $script:panelMultipart.Controls.Add($multipartToolbar)

    # Helper function to re-evaluate and update all file lines in the body text
    function Apply-Attributes-To-AllFileLines {
        $lines = $script:textBody.Text.Split([string[]]@("`r`n", "`n"), [StringSplitOptions]::None)
        $updatedLines = foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            # Regex to capture key, file path (quoted or not), and then optional attributes
            if ($trimmedLine -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                $key = $matches[1].Trim()
                $filePath = if ($matches[3]) { $matches[3] } else { $matches[4] } # Correctly get path if quoted (group 3) or not (group 4)
                $fileString = "@`"$filePath`""

                if ($checkIncludeFilename.Checked) {
                    $fileName = [System.IO.Path]::GetFileName($filePath)
                    $fileString += ";filename=$fileName"
                }
                if ($checkIncludeContentType.Checked) {
                    $mimeType = Get-MimeType -filePath $filePath
                    $fileString += ";type=$mimeType"
                }
                "$key=$fileString"
            } else { $line } # Return non-file lines unchanged
        } # End of foreach ($line in $lines)
        $script:textBody.Text = $updatedLines -join [System.Environment]::NewLine
    }

    function Convert-MultipartBodyToItems {
        param([string]$BodyText)
        $items = @()
        foreach ($line in ($BodyText -split "`r?`n" | Where-Object { $_ -match '\S' })) {
            if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                $key = $matches[1].Trim()
                $filePath = if ($matches[3]) { $matches[3] } else { $matches[4] }
                $attributesRaw = $matches[5]
                $fileName = ""
                $contentType = ""
                if ($attributesRaw -match 'filename=([^;`\r`n]+)') { $fileName = $matches[1].Trim() }
                if ($attributesRaw -match 'type=([^;`\r`n]+)') { $contentType = $matches[1].Trim() }
                $items += [PSCustomObject]@{
                    Key = $key
                    Kind = "File"
                    Value = $filePath
                    FileName = $fileName
                    ContentType = $contentType
                }
            } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)$') {
                $items += [PSCustomObject]@{
                    Key = $matches[1].Trim()
                    Kind = "Value"
                    Value = $matches[2]
                    FileName = ""
                    ContentType = ""
                }
            }
        }
        return $items
    }

    function Set-MultipartItemsToGrid {
        param([array]$Items)
        $script:gridMultipart.Rows.Clear()
        foreach ($item in @($Items)) {
            $rowIndex = $script:gridMultipart.Rows.Add()
            $row = $script:gridMultipart.Rows[$rowIndex]
            $row.Cells["Key"].Value = $item.Key
            $row.Cells["Kind"].Value = if ($item.Kind) { $item.Kind } else { "Value" }
            $row.Cells["Value"].Value = $item.Value
            $row.Cells["FileName"].Value = $item.FileName
            $row.Cells["ContentType"].Value = $item.ContentType
        }
    }

    function Get-MultipartItemsFromGrid {
        $items = @()
        foreach ($row in $script:gridMultipart.Rows) {
            if ($row.IsNewRow) { continue }
            $key = [string]$row.Cells["Key"].Value
            $kind = [string]$row.Cells["Kind"].Value
            $value = [string]$row.Cells["Value"].Value
            $fileName = [string]$row.Cells["FileName"].Value
            $contentType = [string]$row.Cells["ContentType"].Value
            if ([string]::IsNullOrWhiteSpace($key) -and [string]::IsNullOrWhiteSpace($value)) { continue }
            $items += [PSCustomObject]@{
                Key = $key
                Kind = if ([string]::IsNullOrWhiteSpace($kind)) { "Value" } else { $kind }
                Value = $value
                FileName = $fileName
                ContentType = $contentType
            }
        }
        return $items
    }

    function Sync-MultipartGridToBody {
        if (-not $script:gridMultipart) { return }
        $lines = foreach ($item in Get-MultipartItemsFromGrid) {
            if ($item.Kind -eq "File") {
                $fileString = "@`"$($item.Value)`""
                if (-not [string]::IsNullOrWhiteSpace($item.FileName)) { $fileString += ";filename=$($item.FileName)" }
                elseif ($checkIncludeFilename.Checked -and -not [string]::IsNullOrWhiteSpace($item.Value)) {
                    $fileString += ";filename=$([System.IO.Path]::GetFileName($item.Value))"
                }
                if (-not [string]::IsNullOrWhiteSpace($item.ContentType)) { $fileString += ";type=$($item.ContentType)" }
                elseif ($checkIncludeContentType.Checked -and -not [string]::IsNullOrWhiteSpace($item.Value)) {
                    $fileString += ";type=$(Get-MimeType -filePath $item.Value)"
                }
                "$($item.Key)=$fileString"
            } else {
                "$($item.Key)=$($item.Value)"
            }
        }
        $script:textBody.Text = $lines -join [System.Environment]::NewLine
    }

    function Sync-BodyToMultipartGrid {
        if (-not $script:textBody) { return }
        Set-MultipartItemsToGrid -Items (Convert-MultipartBodyToItems -BodyText $script:textBody.Text)
    }
    # Add KeyDown event to Body textbox to handle file selection with Alt+@
    $script:textBody.Add_KeyDown({
        param($sender, $e)
        if ($e.Alt -and $e.KeyCode -eq [System.Windows.Forms.Keys]::D2 -and $script:comboBodyType.SelectedItem -eq "multipart/form-data") {
            # Alt+Shift+2 produces @ character
            $e.SuppressKeyPress = $true
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Filter = "All files (*.*)|*.*"
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                # Find the start of the current line to get the key
                $lineStart = $sender.Text.LastIndexOf("`n", [Math]::Max(0, $sender.SelectionStart - 1)) + 1
                $currentLine = $sender.Text.Substring($lineStart, $sender.SelectionStart - $lineStart)
                $key = ($currentLine -split '=')[0].Trim()

                # Format the file path string, including optional attributes
                $fullPath = $openFileDialog.FileName
                $fileString = "@`"$fullPath`""

                if ($checkIncludeFilename.Checked) {
                    $fileName = [System.IO.Path]::GetFileName($fullPath)
                    $fileString += ";filename=$fileName"
                }
                if ($checkIncludeContentType.Checked) {
                    $mimeType = Get-MimeType -filePath $fullPath
                    $fileString += ";type=$mimeType"
                }

                $currentPos = $sender.SelectionStart
                $sender.Text = $sender.Text.Insert($currentPos, $fileString)
                $sender.SelectionStart = $currentPos + $fileString.Length
                Write-Log "File string inserted: $fileString"
            }
        }
    })
    $btnAddMultipartField.Add_Click({
        $rowIndex = $script:gridMultipart.Rows.Add()
        $row = $script:gridMultipart.Rows[$rowIndex]
        $row.Cells["Kind"].Value = "Value"
        $script:gridMultipart.CurrentCell = $row.Cells["Key"]
        $script:gridMultipart.BeginEdit($true) | Out-Null
        Sync-MultipartGridToBody
    })
    $btnAddMultipartFile.Add_Click({
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter = "All files (*.*)|*.*" }
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $rowIndex = $script:gridMultipart.Rows.Add()
            $row = $script:gridMultipart.Rows[$rowIndex]
            $row.Cells["Kind"].Value = "File"
            $row.Cells["Value"].Value = $openFileDialog.FileName
            if ($checkIncludeFilename.Checked) { $row.Cells["FileName"].Value = [System.IO.Path]::GetFileName($openFileDialog.FileName) }
            if ($checkIncludeContentType.Checked) { $row.Cells["ContentType"].Value = Get-MimeType -filePath $openFileDialog.FileName }
            Sync-MultipartGridToBody
        }
    })
    $btnRemoveMultipartRow.Add_Click({
        foreach ($row in @($script:gridMultipart.SelectedRows)) {
            if (-not $row.IsNewRow) { $script:gridMultipart.Rows.Remove($row) }
        }
        Sync-MultipartGridToBody
    })
    $script:gridMultipart.Add_CurrentCellDirtyStateChanged({
        if ($script:gridMultipart.IsCurrentCellDirty) { $script:gridMultipart.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
    })
    $script:gridMultipart.Add_CellValueChanged({ Sync-MultipartGridToBody })
    $script:gridMultipart.Add_RowsRemoved({ Sync-MultipartGridToBody })

    # --- GraphQL Controls ---
    $script:panelGraphQL = New-Object System.Windows.Forms.Panel -Property @{ Dock='Fill'; Visible=$false }
    $splitGraphQL = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock='Fill'; Orientation='Vertical'; SplitterDistance=260 }
    
    $lblGqlQuery = New-Label -Text "Query:" -Property @{ Dock='Top' }
    $script:txtGqlQuery = New-TextBox -Multiline $true -Property @{ Dock='Fill'; ScrollBars='Vertical'; Font=New-Object System.Drawing.Font("Courier New", 9) }
    
    $lblGqlVars = New-Label -Text "Variables (JSON):" -Property @{ Dock='Top' }
    $script:txtGqlVars = New-TextBox -Multiline $true -Property @{ Dock='Fill'; ScrollBars='Vertical'; Font=New-Object System.Drawing.Font("Courier New", 9) }
    
    $splitGraphQL.Panel1.Controls.Add($script:txtGqlQuery)
    $splitGraphQL.Panel1.Controls.Add($lblGqlQuery)
    $splitGraphQL.Panel2.Controls.Add($script:txtGqlVars)
    $splitGraphQL.Panel2.Controls.Add($lblGqlVars)
    $script:panelGraphQL.Controls.Add($splitGraphQL)

    $tabRequestBody.Controls.AddRange(@($script:textBody, $script:panelMultipart, $script:panelGraphQL, $panelBodyLabel, $bodyTopPanel))

    $tabRequestHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Headers"; Padding = [System.Windows.Forms.Padding]::new(5) }

    $labelHeaders = New-Label -Text "Headers (key:value per line):" -Property @{ Dock = 'Top'; Height = 25; TextAlign = 'MiddleLeft' }
    $script:textHeaders = New-TextBox -Multiline $true -Property @{
        Name       = 'textHeaders'
        Dock       = 'Fill'
        ScrollBars = "Both"
    }
    $tabRequestHeaders.Controls.AddRange(@($script:textHeaders, $labelHeaders))

    $tabPreRequest = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Pre-request"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $labelPreRequest = New-Label -Text "PowerShell script to run before request. Access environment via `$Environment." -Property @{ Dock = 'Top'; Height = 25; TextAlign = 'MiddleLeft' }
    $script:textPreRequest = New-TextBox -Multiline $true -Property @{
        Name       = 'textPreRequest'
        Dock       = 'Fill'
        Font       = New-Object System.Drawing.Font("Courier New", 9)
        ScrollBars = "Both"
    }
    $tabPreRequest.Controls.AddRange(@($script:textPreRequest, $labelPreRequest))

    $tabRequestTests = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Tests"; Padding = [System.Windows.Forms.Padding]::new(5) }

    # --- Tests Snippets Library (Sidebar) ---
    $script:testSnippets = @(
        [PSCustomObject]@{ Name = "Check Status 200"; Code = "Assert-StatusIs -StatusCode `$statusCode -ExpectedStatus 200" }
        [PSCustomObject]@{ Name = "Check Status 201"; Code = "Assert-StatusIs -StatusCode `$statusCode -ExpectedStatus 201" }
        [PSCustomObject]@{ Name = "Check JSON Value"; Code = "Assert-Equal -Value `$jsonBody.path.to.value -Expected `"expected`"" }
        [PSCustomObject]@{ Name = "Check Body Contains"; Code = "Assert-Contains -String `$body -Substring `"expected substring`"" }
        [PSCustomObject]@{ Name = "Header Exists"; Code = "Assert-Contains -String (`$headers.Keys -join `",`") -Substring `"Header-Name`"" }
        [PSCustomObject]@{ Name = "Check JSON Exists"; Code = "if (-not `$jsonBody) { `$script:testResults.Add([PSCustomObject]@{ Status='FAIL'; Message='Response body is not valid JSON.' }) }" }
    )

    $testsSplit = New-Object System.Windows.Forms.SplitContainer
    $testsSplit.Dock = 'Fill'
    $testsSplit.Orientation = 'Vertical'
    $testsSplit.SplitterDistance = 220
    $testsSplit.Panel1MinSize = 160
    $testsSplit.BackColor = $script:Theme.FormBackground

    $snippetsGroup = New-Object System.Windows.Forms.GroupBox -Property @{
        Text = "Snippets"
        Dock = 'Fill'
        Padding = [System.Windows.Forms.Padding]::new(8)
        BackColor = $script:Theme.GroupBackground
    }

    $snippetsLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 2
    }
    $snippetsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $snippetsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $listSnippets = New-Object System.Windows.Forms.ListBox -Property @{
        Dock = 'Fill'
    }
    $listSnippets.Items.AddRange($script:testSnippets.Name)

    $btnInsertSnippet = New-Button -Text "Insert" -Style 'Secondary' -Property @{
        Dock = 'Fill'
        Height = 30
        Margin = [System.Windows.Forms.Padding]::new(0, 6, 0, 0)
    } -OnClick {
        if ($listSnippets.SelectedIndex -lt 0) { return }
        $code = $script:testSnippets[$listSnippets.SelectedIndex].Code
        $pos = $script:textTests.SelectionStart
        $prefix = ""
        if ($pos -gt 0 -and $script:textTests.Text[$pos - 1] -ne "`n") { $prefix = "`r`n" }
        $insertText = "$prefix$code"
        $script:textTests.Text = $script:textTests.Text.Insert($pos, $insertText)
        $script:textTests.SelectionStart = $pos + $insertText.Length
        $script:textTests.Focus()
    }

    $listSnippets.Add_DoubleClick({ $btnInsertSnippet.PerformClick() })

    $snippetsLayout.Controls.Add($listSnippets, 0, 0)
    $snippetsLayout.Controls.Add($btnInsertSnippet, 0, 1)
    $snippetsGroup.Controls.Add($snippetsLayout)
    $testsSplit.Panel1.Controls.Add($snippetsGroup)

    # --- Tests Editor (Right Panel) ---
    $testsEditorLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 2
    }
    $testsEditorLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $testsEditorLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $labelTests = New-Label -Text "PowerShell tests to run against the response. Use variables like `$statusCode, `$body, `$jsonBody." -Property @{ Dock = 'Top'; Height = 25; TextAlign = 'MiddleLeft' }
    $script:textTests = New-TextBox -Multiline $true -Property @{
        Name       = 'textTests'
        Dock       = 'Fill'
        Font       = New-Object System.Drawing.Font("Courier New", 9)
        ScrollBars = "Both"
    }
    $toolTip.SetToolTip($script:textTests, "Example: Assert-Equal -Value `$statusCode -Expected 200")

    $testsEditorLayout.Controls.Add($labelTests, 0, 0)
    $testsEditorLayout.Controls.Add($script:textTests, 0, 1)
    $testsSplit.Panel2.Controls.Add($testsEditorLayout)

    $tabRequestTests.Controls.Add($testsSplit)

    # Create the main authentication panel for the request and get the tab page from it
    $script:authPanel = New-AuthPanel #FIX: Corrected function call
    $tabAuth = $script:authPanel.Tab

    function Get-ActiveRequestTabState {
        if (-not $script:activeRequestTabId) { return $null }
        return @($script:requestTabs | Where-Object { $_.Id -eq $script:activeRequestTabId })[0]
    }

    function Update-RequestTabNamesInUi {
        if (-not $script:requestTabsStrip) { return }
        foreach ($page in $script:requestTabsStrip.TabPages) {
            $tabState = @($script:requestTabs | Where-Object { $_.Id -eq $page.Tag })[0]
            if ($tabState) { $page.Text = $tabState.Name }
        }
    }

    function Get-RequestTabDisplayName {
        param([object]$RequestState, [int]$Index = 0)
        if ($RequestState -and -not [string]::IsNullOrWhiteSpace($RequestState.Name)) { return $RequestState.Name }
        if ($RequestState -and -not [string]::IsNullOrWhiteSpace($RequestState.Url)) {
            $method = if ($RequestState.Method) { $RequestState.Method } else { "REQ" }
            return "$method $($RequestState.Url)"
        }
        return "Request $Index"
    }

    function Capture-CurrentRequestState {
        $existing = Get-ActiveRequestTabState
        $captured = New-RequestTabState -Name "$(if ($existing) { $existing.Name } else { "Request" })" `
            -Method ([string]$script:comboMethod.SelectedItem) `
            -Url $script:textUrl.Text `
            -Headers $script:textHeaders.Text `
            -Body $script:textBody.Text `
            -BodyType ([string]$script:comboBodyType.SelectedItem) `
            -OutputFormat $script:textOutputFormat.Text `
            -Tests $script:textTests.Text `
            -PreRequestScript $script:textPreRequest.Text `
            -Environment ([string]$script:comboEnvironment.SelectedItem) `
            -Authentication (& $script:authPanel.GetAuthData) `
            -GqlQuery $script:txtGqlQuery.Text `
            -GqlVars $script:txtGqlVars.Text `
            -IncludeFilename $checkIncludeFilename.Checked `
            -IncludeContentType $checkIncludeContentType.Checked
        if ($existing) {
            if ($existing.Id) {
                $captured.Id = $existing.Id
                $captured.Name = if (-not [string]::IsNullOrWhiteSpace($existing.Name)) { $existing.Name } else { Get-RequestTabDisplayName -RequestState $captured }
            }
        } else {
            $captured.Name = Get-RequestTabDisplayName -RequestState $captured
        }
        return $captured
    }

    function Save-ActiveRequestTabState {
        $current = Get-ActiveRequestTabState
        if (-not $current -or $script:isSwitchingRequestTab) { return }
        if ($script:comboBodyType.SelectedItem -eq "multipart/form-data") { Sync-MultipartGridToBody }
        $captured = Capture-CurrentRequestState
        for ($i = 0; $i -lt $script:requestTabs.Count; $i++) {
            if ($script:requestTabs[$i].Id -eq $captured.Id) {
                $script:requestTabs[$i] = $captured
                break
            }
        }
        Save-RequestTabs
        Update-RequestTabNamesInUi
    }

    function Set-BodyEditorMode {
        if ($script:comboBodyType.SelectedItem -eq "multipart/form-data") {
            $checkIncludeFilename.Visible = $true
            $checkIncludeContentType.Visible = $true
            $labelBody.Text = "Multipart fields and files:"
            $script:textBody.Visible = $false
            $script:panelMultipart.Visible = $true
            $script:panelGraphQL.Visible = $false
            Sync-BodyToMultipartGrid
        } elseif ($script:comboBodyType.SelectedItem -eq "GraphQL") {
            $checkIncludeFilename.Visible = $false
            $checkIncludeContentType.Visible = $false
            $labelBody.Text = "GraphQL query and variables:"
            $script:textBody.Visible = $false
            $script:panelMultipart.Visible = $false
            $script:panelGraphQL.Visible = $true
        } else {
            $checkIncludeFilename.Visible = $false
            $checkIncludeContentType.Visible = $false
            $labelBody.Text = "Body (raw content):"
            $script:textBody.Visible = $true
            $script:panelMultipart.Visible = $false
            $script:panelGraphQL.Visible = $false
        }
    }

    function Apply-RequestStateToUi {
        param([object]$RequestState)
        if (-not $RequestState) { return }
        Ensure-RequestTabDefaults -TabState $RequestState
        $script:isSwitchingRequestTab = $true
        try {
            $script:textUrl.Text = $RequestState.Url
            $script:comboMethod.SelectedItem = $RequestState.Method
            $script:comboBodyType.SelectedItem = $RequestState.BodyType
            $script:textHeaders.Text = $RequestState.Headers
            $script:textBody.Text = $RequestState.Body
            $script:textOutputFormat.Text = $RequestState.OutputFormat
            $script:textTests.Text = $RequestState.Tests
            $script:textPreRequest.Text = $RequestState.PreRequestScript
            $script:txtGqlQuery.Text = $RequestState.GqlQuery
            $script:txtGqlVars.Text = $RequestState.GqlVars
            $checkIncludeFilename.Checked = [bool]$RequestState.IncludeFilename
            $checkIncludeContentType.Checked = [bool]$RequestState.IncludeContentType
            Set-BodyEditorMode

            if ($requestState.Environment -and $script:comboEnvironment.Items.Contains($RequestState.Environment)) {
                $script:comboEnvironment.SelectedItem = $RequestState.Environment
            } else {
                $script:comboEnvironment.SelectedItem = "No Environment"
            }

            if ($RequestState.Authentication) {
                $auth = $RequestState.Authentication
                $script:authPanel.ComboAuthType.SelectedItem = $auth.Type
                & $script:authPanel.SwitchPanel
                switch ($auth.Type) {
                    "API Key"      { $script:authPanel.TextApiKeyName.Text = $auth.Key; $script:authPanel.TextApiKeyValue.Text = $auth.Value; $script:authPanel.ComboApiKeyAddTo.SelectedItem = $auth.AddTo }
                    "Bearer Token" { $script:authPanel.TextBearerToken.Text = $auth.Token }
                    "Basic Auth"   { $script:authPanel.TextBasicUser.Text = $auth.Username; $script:authPanel.TextBasicPass.Text = $auth.Password }
                    "Auth2"        {
                        $script:authPanel.TextAuth2ClientId.Text = $auth.ClientId
                        $script:authPanel.TextAuth2ClientSecret.Text = $auth.ClientSecret
                        $script:authPanel.TextAuth2AuthEndpoint.Text = $auth.AuthEndpoint
                        $script:authPanel.TextAuth2RedirectUri.Text = $auth.RedirectUri
                        $script:authPanel.TextAuth2TokenEndpoint.Text = $auth.TokenEndpoint
                        $script:authPanel.TextAuth2Scope.Text = $auth.Scope
                        $script:authPanel.TextAuth2AccessToken.Text = $auth.AccessToken
                        $script:authPanel.TextAuth2RefreshToken.Text = $auth.RefreshToken
                        $script:authPanel.TextAuth2ExpiresIn.Text = $auth.ExpiresIn
                        $script:authPanel.TextAuth2AccessToken.Tag = $auth.TokenExpiryTimestamp
                    }
                    "Client Certificate" {
                        $script:authPanel.ComboCertSource.SelectedItem = $auth.Source
                        $script:authPanel.TextCertPath.Text = $auth.Path
                        $script:authPanel.TextCertPass.Text = $auth.Password
                        $script:authPanel.TextCertThumb.Text = $auth.Thumbprint
                    }
                    default { $script:authPanel.ComboAuthType.SelectedItem = "No Auth"; & $script:authPanel.SwitchPanel }
                }
            } else {
                $script:authPanel.ComboAuthType.SelectedItem = "No Auth"
                & $script:authPanel.SwitchPanel
            }
        } finally {
            $script:isSwitchingRequestTab = $false
        }
    }

    function Refresh-RequestTabsStrip {
        if (-not $script:requestTabsStrip) { return }
        $script:isSwitchingRequestTab = $true
        try {
            $script:requestTabsStrip.TabPages.Clear()
            $idx = 1
            foreach ($tabState in $script:requestTabs) {
                Ensure-RequestTabDefaults -TabState $tabState
                $page = New-Object System.Windows.Forms.TabPage
                $page.Text = Get-RequestTabDisplayName -RequestState $tabState -Index $idx
                $page.Tag = $tabState.Id
                [void]$script:requestTabsStrip.TabPages.Add($page)
                if ($tabState.Id -eq $script:activeRequestTabId) { $script:requestTabsStrip.SelectedTab = $page }
                $idx++
            }
        } finally {
            $script:isSwitchingRequestTab = $false
        }
        Update-RequestTabNamesInUi
    }

    function Set-ActiveRequestTab {
        param([string]$TabId)
        if ([string]::IsNullOrWhiteSpace($TabId)) { return }
        Save-ActiveRequestTabState
        $script:activeRequestTabId = $TabId
        $target = @($script:requestTabs | Where-Object { $_.Id -eq $TabId })[0]
        Apply-RequestStateToUi -RequestState $target
        Save-RequestTabs
        Update-RequestTabNamesInUi
    }

    function Add-RequestTab {
        param([object]$InitialState = $null)
        Save-ActiveRequestTabState
        $newState = if ($InitialState) { Copy-RequestData $InitialState } else { $null }
        if ($newState) {
            Ensure-RequestTabDefaults -TabState $newState
            $newState.Id = [guid]::NewGuid().ToString()
            if ([string]::IsNullOrWhiteSpace($newState.Name)) {
                $newState.Name = "Request $($script:requestTabs.Count + 1)"
            }
        } else {
            $newState = New-RequestTabState -Name "Request $($script:requestTabs.Count + 1)" -Environment ([string]$script:comboEnvironment.SelectedItem) -IncludeFilename $checkIncludeFilename.Checked -IncludeContentType $checkIncludeContentType.Checked
        }
        $script:requestTabs += $newState
        $script:activeRequestTabId = $newState.Id
        Refresh-RequestTabsStrip
        Apply-RequestStateToUi -RequestState $newState
        Save-RequestTabs
    }

    function Remove-ActiveRequestTab {
        if (-not $script:activeRequestTabId) { return }
        if ($script:requestTabs.Count -le 1) {
            [System.Windows.Forms.MessageBox]::Show("At least one request tab must remain open.", "Close Tab", "OK", "Information")
            return
        }
        $currentIndex = [array]::IndexOf(@($script:requestTabs.Id), $script:activeRequestTabId)
        $script:requestTabs = @($script:requestTabs | Where-Object { $_.Id -ne $script:activeRequestTabId })
        if ($currentIndex -ge $script:requestTabs.Count) { $currentIndex = $script:requestTabs.Count - 1 }
        $script:activeRequestTabId = $script:requestTabs[$currentIndex].Id
        Refresh-RequestTabsStrip
        Apply-RequestStateToUi -RequestState (Get-ActiveRequestTabState)
        Save-RequestTabs
    }

    function Show-RequestTemplatesWindow {
        $templateForm = New-Object System.Windows.Forms.Form -Property @{
            Text = "Request Templates"
            Size = New-Object System.Drawing.Size(520, 420)
            StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
            BackColor = $script:Theme.GroupBackground
        }

        $listTemplates = New-Object System.Windows.Forms.ListBox -Property @{ Dock = 'Fill' }
        foreach ($template in $script:requestTemplates) { [void]$listTemplates.Items.Add($template.Name) }

        $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
            Dock = 'Bottom'
            Height = 46
            FlowDirection = 'RightToLeft'
            Padding = [System.Windows.Forms.Padding]::new(8)
        }

        $btnCloseTemplateForm = New-Button -Text "Close" -Property @{ Width = 90; Height = 30 } -OnClick { $templateForm.Close() }
        $btnApplyTemplate = New-Button -Text "Apply" -Style 'Primary' -Property @{ Width = 90; Height = 30; Margin = [System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
            if ($listTemplates.SelectedIndex -lt 0) { return }
            $template = $script:requestTemplates[$listTemplates.SelectedIndex]
            $activeState = Get-ActiveRequestTabState
            if ($activeState) {
                $templateCopy = Copy-RequestData $template
                $templateCopy.Id = $activeState.Id
                $templateCopy.Name = $activeState.Name
                for ($i = 0; $i -lt $script:requestTabs.Count; $i++) {
                    if ($script:requestTabs[$i].Id -eq $activeState.Id) {
                        $script:requestTabs[$i] = $templateCopy
                        break
                    }
                }
                Apply-RequestStateToUi -RequestState $templateCopy
                Save-RequestTabs
                Update-RequestTabNamesInUi
            }
            $templateForm.Close()
        }
        $btnSaveTemplate = New-Button -Text "Save Current" -Property @{ Width = 110; Height = 30; Margin = [System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
            Save-ActiveRequestTabState
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a template name:", "Save Template", "Template $($script:requestTemplates.Count + 1)")
            if ([string]::IsNullOrWhiteSpace($name)) { return }
            $templateState = Capture-CurrentRequestState
            $templateState.Id = [guid]::NewGuid().ToString()
            $templateState.Name = $name.Trim()
            $script:requestTemplates += $templateState
            Save-RequestTemplates
            [void]$listTemplates.Items.Add($templateState.Name)
        }
        $btnDeleteTemplate = New-Button -Text "Delete" -Style 'Danger' -Property @{ Width = 90; Height = 30; Margin = [System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
            if ($listTemplates.SelectedIndex -lt 0) { return }
            $script:requestTemplates = @($script:requestTemplates | Where-Object { $_.Name -ne $listTemplates.SelectedItem })
            Save-RequestTemplates
            $listTemplates.Items.RemoveAt($listTemplates.SelectedIndex)
        }

        $buttonPanel.Controls.AddRange(@($btnCloseTemplateForm, $btnApplyTemplate, $btnSaveTemplate, $btnDeleteTemplate))
        $templateForm.Controls.Add($listTemplates)
        $templateForm.Controls.Add($buttonPanel)
        $templateForm.ShowDialog($form) | Out-Null
    }

    $btnNewRequestTab.Add_Click({ Add-RequestTab })
    $btnDuplicateRequestTab.Add_Click({
        $activeState = Get-ActiveRequestTabState
        if ($activeState) {
            Add-RequestTab -InitialState $activeState
        }
    })
    $btnCloseRequestTab.Add_Click({ Remove-ActiveRequestTab })
    $btnTemplates.Add_Click({ Show-RequestTemplatesWindow })
    $script:requestTabsStrip.Add_SelectedIndexChanged({
        if ($script:isSwitchingRequestTab) { return }
        if ($script:requestTabsStrip.SelectedTab -and $script:requestTabsStrip.SelectedTab.Tag) {
            Set-ActiveRequestTab -TabId ([string]$script:requestTabsStrip.SelectedTab.Tag)
        }
    })
    $script:requestTabsStrip.Add_MouseDoubleClick({
        param($sender, $e)
        $tabControl = $sender
        $selectedPage = $tabControl.SelectedTab
        if (-not $selectedPage) { return }

        $tabId = $selectedPage.Tag
        $tabState = @($script:requestTabs | Where-Object { $_.Id -eq $tabId })[0]
        if (-not $tabState) { return }

        $newName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new tab name:", "Rename Tab", $tabState.Name)
        if (-not [string]::IsNullOrWhiteSpace($newName)) {
            $tabState.Name = $newName
            $selectedPage.Text = $newName
            Save-RequestTabs
        }
    })
    $script:requestTabsStrip.Add_MouseClick({
        param($sender, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Middle) {
            for ($i = 0; $i -lt $script:requestTabsStrip.TabCount; $i++) {
                if ($script:requestTabsStrip.GetTabRect($i).Contains($e.Location)) {
                    $script:requestTabsStrip.SelectedIndex = $i
                    Remove-ActiveRequestTab
                    break
                }
            }
        }
    })

    # The main "Send Request" button. Its click handler orchestrates the entire API call process.
    $btnSubmit = New-Button -Text "Send Request" -Style 'Primary' -OnClick {
        $btnSubmit.Enabled = $false
        $btnCancel.Enabled = $true
        $btnRepeat.Enabled = $false
        Invoke-RequestExecution
    } -Property @{ Size = New-Object System.Drawing.Size(165, 40); Margin = [System.Windows.Forms.Padding]::new(0,0,10,0) }

    # Button to repeat the request after receiving response
    $btnRepeat = New-Button -Text "Repeat" -OnClick {
        if ($script:settings.EnableRepeatRequest -eq $false) {
            [System.Windows.Forms.MessageBox]::Show("Repeat Request is not enabled. Enable it in Settings > Configuration > Enable Repeat Request.", "Feature Disabled", "OK", "Information")
            return
        }
        
        $repeatCount = [int][Microsoft.VisualBasic.Interaction]::InputBox("Enter number of times to repeat the request:`n(Max: $($script:settings.MaxRepeatCount))", "Repeat Request", "1")
        
        if ($repeatCount -le 0) { 
            [System.Windows.Forms.MessageBox]::Show("Please enter a positive number.", "Invalid Input", "OK", "Warning")
            return 
        }
        
        if ($repeatCount -gt $script:settings.MaxRepeatCount) {
            [System.Windows.Forms.MessageBox]::Show("Number of repeats exceeds maximum allowed ($($script:settings.MaxRepeatCount)).", "Limit Exceeded", "OK", "Warning")
            return
        }
        
        $script:repeatCount = $repeatCount
        $script:currentRepeatIteration = 0
        $script:repeatSuccessCount = 0
        $script:repeatFailCount = 0
        $script:isRepeating = $true
        
        Write-Log "Starting repeat request: $repeatCount iterations" -Level Debug
        
        # Manually trigger the request execution instead of clicking the button
        # This avoids UI race conditions where the button might be disabled.
        $btnSubmit.Enabled = $false
        $btnCancel.Enabled = $true
        $btnRepeat.Enabled = $false
        Invoke-RequestExecution
    } -Property @{ Size = New-Object System.Drawing.Size(165, 40); Margin = [System.Windows.Forms.Padding]::new(0,0,10,0) }

    # Button to stop the currently running background job.
    $btnCancel = New-Button -Text "Cancel" -OnClick {
        if ($script:isCollectionRunning) {
            Write-Log "Cancel button clicked during collection run. Requesting runner stop."
            Request-CollectionRunStop -Summary "Stopping collection run..."
            return
        }
        if ($script:currentPowerShell) {
            Write-Log "Cancel button clicked. Stopping pipeline."
            try { $script:currentPowerShell.Stop() } catch {}
        }
        $script:isRepeating = $false
    } -Property @{ Size = New-Object System.Drawing.Size(165, 40); Enabled = $false; Margin = [System.Windows.Forms.Padding]::new(0,0,10,0) }

    $panelOutputButtons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Fill'
        FlowDirection = 'LeftToRight'
    }
    $panelOutputButtons.Controls.AddRange(@($btnSubmit, $btnRepeat, $btnCancel))
    
    $panelOutputActions.Controls.Add($panelOutputButtons)

    $form.Tag = [PSCustomObject]@{
        btnSubmit = $btnSubmit
        btnCancel = $btnCancel
        btnRepeat = $btnRepeat
    }

    # GroupBox that contains all the response-related tabs.
    $groupResponse = New-Object System.Windows.Forms.GroupBox -Property @{
        Anchor    = "Top, Bottom, Left, Right"
        Text      = "Response"
        Padding   = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }

    # Context menu for the response panel to allow undocking
    $responsePanelContextMenu = New-Object System.Windows.Forms.ContextMenuStrip    
    $dockingMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Docking Options")

    # Helper function to set and save the dock state
    $setDockState = {
        param([string]$newState)
        # If the new state is different, or if we are toggling off the 'Undocked' state
        if ($script:responseDockState -ne $newState -or ($script:responseDockState -eq 'Undocked' -and $newState -eq 'Undocked')) {
            # If currently docked, save the state before undocking
            if ($script:responseDockState -ne 'Undocked') {
                $script:lastDockState = $script:responseDockState
            }
 
            # If we are clicking 'Undocked' while already undocked, re-dock to the last state
            if ($script:responseDockState -eq 'Undocked' -and $newState -eq 'Undocked') {
                $newState = $script:lastDockState
            }
 
            $script:responseDockState = $newState
            $script:settings.ResponseDockState = $newState
            Save-Settings
            Update-Layout
        }
    }
    $dockBottomMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Dock to Bottom", $null, { & $setDockState 'Bottom' })
    $dockLeftMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Dock to Left", $null, { & $setDockState 'Left' })
    $dockRightMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Dock to Right", $null, { & $setDockState 'Right' })
    $undockMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Undock Panel", $null, { & $setDockState 'Undocked' })

    $dockingMenuItem.DropDownItems.AddRange(@($dockBottomMenuItem, $dockLeftMenuItem, $dockRightMenuItem, (New-Object System.Windows.Forms.ToolStripSeparator), $undockMenuItem))
    $responsePanelContextMenu.Items.Add($dockingMenuItem)
    $groupResponse.ContextMenuStrip = $responsePanelContextMenu

    # Generates a code snippet string based on a request object.
    function Generate-CodeSnippet {
        param(
            [PSCustomObject]$RequestItem,
            [string]$Language = "cURL"
        )
        if (-not $RequestItem) { return "" }

        $method = $RequestItem.Method
        $url = $RequestItem.Url
        $headersRaw = $RequestItem.Headers
        $bodyRaw = $RequestItem.Body
        $bodyType = $RequestItem.BodyType

        # Parse headers
        $headers = @{}
        foreach ($line in $headersRaw -split "`n") {
            if ($line -match "^\s*(.+?):\s*(.+)$") {
                $headers[$matches[1]] = $matches[2]
            }
        }

        $sb = New-Object System.Text.StringBuilder

        switch ($Language) {
            "cURL" {
                $curlParts = @("curl -X '$method' \")
                foreach ($key in $headers.Keys) {
                    $curlParts += "  -H '$($key): $($headers[$key])' \"
                }

                if ($bodyType -eq "multipart/form-data") {
                    if (-not $headers.ContainsKey("Content-Type")) {
                        $curlParts += "  -H 'Content-Type: multipart/form-data' \"
                    }
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim()
                            if ($matches[3]) { $filePath = $matches[3] } else { $filePath = $matches[4] }
                            $attributes = $matches[5]
                            $curlParts += "  -F '$key=@$filePath$attributes' \"
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $value = $matches[2].Trim()
                            $curlParts += "  -F '$key=$value' \"
                        }
                    }
                } else {
                if (-not $headers.ContainsKey("Content-Type")) { 
                    if ($bodyRaw) { $rawContentType = $bodyType } else { $rawContentType = 'text/plain' }
                    $curlParts += "  -H 'Content-Type: $rawContentType' \" 
                }
                    if ($bodyRaw) { $curlParts += "  -d '$($bodyRaw -replace "'", "'\''")' \" }
                }
                $curlParts += "  '$url'"
                return ($curlParts -join "`n").TrimEnd(' \')
            }
            "PowerShell" {
                $sb.AppendLine("`$headers = @{") | Out-Null
                foreach ($key in $headers.Keys) {
                    $sb.AppendLine("    '$key' = '$($headers[$key])'") | Out-Null
                }
                $sb.AppendLine("}") | Out-Null
                $sb.AppendLine("") | Out-Null
                
                $params = "-Method $method -Uri '$url' -Headers `$headers"
                
                if ($bodyRaw) {
                    $sb.AppendLine("`$body = @'") | Out-Null
                    $sb.AppendLine($bodyRaw) | Out-Null
                    $sb.AppendLine("'@") | Out-Null
                    $params += " -Body `$body"
                    if (-not $headers.ContainsKey("Content-Type") -and $bodyType -ne 'multipart/form-data') {
                         $params += " -ContentType '$bodyType'"
                    }
                }
                $sb.AppendLine("Invoke-RestMethod $params") | Out-Null
                return $sb.ToString()
            }
            "Python" {
                $sb.AppendLine("import requests") | Out-Null
                $sb.AppendLine("") | Out-Null
                $sb.AppendLine("url = '$url'") | Out-Null
                $sb.AppendLine("headers = {") | Out-Null
                foreach ($key in $headers.Keys) {
                    if ($key -ne "Content-Type") {
                        $sb.AppendLine("    '$key': '$($headers[$key])',") | Out-Null
                    }
                }
                $sb.AppendLine("}") | Out-Null
                
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("files = [") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim()
                            $path = if ($matches[3]) { $matches[3] } else { $matches[4] }
                            $attrs = $matches[5]
                            $fn = [System.IO.Path]::GetFileName($path)
                            $ct = $null
                            if ($attrs -match 'filename=([^;]+)') { $fn = $matches[1] }
                            if ($attrs -match 'type=([^;]+)') { $ct = $matches[1] }
                            $tuple = "('$key', ('$fn', open(r'$path', 'rb')"
                            if ($ct) { $tuple += ", '$ct'" }
                            $tuple += "))"
                            $sb.AppendLine("  $tuple,") | Out-Null
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $val = $matches[2].Trim()
                            $sb.AppendLine("  ('$key', (None, '$val')),") | Out-Null
                        }
                    }
                    $sb.AppendLine("]") | Out-Null
                    $sb.AppendLine("response = requests.request('$method', url, headers=headers, files=files)") | Out-Null
                } else {
                    if ($bodyRaw) {
                        $sb.AppendLine("payload = '''$bodyRaw'''") | Out-Null
                        $sb.AppendLine("response = requests.request('$method', url, headers=headers, data=payload)") | Out-Null
                    } else {
                        $sb.AppendLine("response = requests.request('$method', url, headers=headers)") | Out-Null
                    }
                }
                $sb.AppendLine("print(response.text)") | Out-Null
                return $sb.ToString()
            }
            "JavaScript" {
                $sb.AppendLine("const myHeaders = new Headers();") | Out-Null
                foreach ($key in $headers.Keys) {
                    if ($key -ne "Content-Type") {
                        $sb.AppendLine("myHeaders.append('$key', '$($headers[$key])');") | Out-Null
                    }
                }
                $sb.AppendLine("") | Out-Null
                
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("const formdata = new FormData();") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim()
                            $path = if ($matches[3]) { $matches[3] } else { $matches[4] }
                            $attrs = $matches[5]
                            $fn = [System.IO.Path]::GetFileName($path)
                            if ($attrs -match 'filename=([^;]+)') { $fn = $matches[1] }
                            $sb.AppendLine("formdata.append('$key', fileInput.files[0], '$fn');") | Out-Null
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $val = $matches[2].Trim()
                            $sb.AppendLine("formdata.append('$key', '$val');") | Out-Null
                        }
                    }
                    $sb.AppendLine("") | Out-Null
                    $sb.AppendLine("const requestOptions = {") | Out-Null
                    $sb.AppendLine("  method: '$method',") | Out-Null
                    $sb.AppendLine("  headers: myHeaders,") | Out-Null
                    $sb.AppendLine("  body: formdata,") | Out-Null
                    $sb.AppendLine("  redirect: 'follow'") | Out-Null
                    $sb.AppendLine("};") | Out-Null
                } else {
                    $sb.AppendLine("const requestOptions = {") | Out-Null
                    $sb.AppendLine("  method: '$method',") | Out-Null
                    $sb.AppendLine("  headers: myHeaders,") | Out-Null
                    if ($bodyRaw) {
                        $sb.AppendLine("  body: `$(`"$bodyRaw`"),") | Out-Null
                    }
                    $sb.AppendLine("  redirect: 'follow'") | Out-Null
                    $sb.AppendLine("};") | Out-Null
                }
                $sb.AppendLine("") | Out-Null
                $sb.AppendLine("fetch('$url', requestOptions)") | Out-Null
                $sb.AppendLine("  .then(response => response.text())") | Out-Null
                $sb.AppendLine("  .then(result => console.log(result))") | Out-Null
                $sb.AppendLine("  .catch(error => console.error('error', error));") | Out-Null
                return $sb.ToString()
            }
            "C#" {
                $sb.AppendLine("var client = new HttpClient();") | Out-Null
                $sb.AppendLine("var request = new HttpRequestMessage(new HttpMethod(`"$method`"), `"$url`");") | Out-Null
                foreach ($key in $headers.Keys) {
                    if ($key -ne "Content-Type") {
                        $sb.AppendLine("request.Headers.Add(`"$key`", `"$($headers[$key])`");") | Out-Null
                    }
                }
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("var content = new MultipartFormDataContent();") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim(); $path = if ($matches[3]) { $matches[3] } else { $matches[4] }; $fn = [System.IO.Path]::GetFileName($path); $safePath = $path.Replace('\', '\\')
                            $sb.AppendLine("content.Add(new StreamContent(File.OpenRead(`"$safePath`")), `"$key`", `"$fn`");") | Out-Null
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim(); $val = $matches[2].Trim()
                            $sb.AppendLine("content.Add(new StringContent(`"$val`"), `"$key`");") | Out-Null
                        }
                    }
                    $sb.AppendLine("request.Content = content;") | Out-Null
                } elseif ($bodyRaw) {
                    $mediaType = if ($headers.ContainsKey("Content-Type")) { $headers["Content-Type"] } elseif ($bodyType) { $bodyType } else { "text/plain" }
                    $safeBody = $bodyRaw.Replace('\', '\\').Replace('"', '\"')
                    $sb.AppendLine("var content = new StringContent(`"$safeBody`", null, `"$mediaType`");") | Out-Null
                    $sb.AppendLine("request.Content = content;") | Out-Null
                }
                $sb.AppendLine("var response = await client.SendAsync(request);") | Out-Null
                $sb.AppendLine("response.EnsureSuccessStatusCode();") | Out-Null
                $sb.AppendLine("Console.WriteLine(await response.Content.ReadAsStringAsync());") | Out-Null
                return $sb.ToString()
            }
        }
        return ""
    }

    # Helper to populate JSON TreeView
    function Populate-JsonTree {
        param($JsonData, $NodesCollection)
        $NodesCollection.Clear()
        $NodesCollection.Owner.BeginUpdate()
        
        function Add-Node {
            param($ParentNodes, $Obj, $Name)
            $nodeText = if ($Name) { "$Name" } else { "Item" }
            $tag = [PSCustomObject]@{ Key = $Name; Value = $Obj }
            
            if ($Obj -eq $null) {
                $newNode = New-Object System.Windows.Forms.TreeNode("${nodeText}: null")
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
            } elseif ($Obj -is [PSCustomObject] -or $Obj -is [hashtable]) {
                $newNode = New-Object System.Windows.Forms.TreeNode($nodeText)
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
                $props = if ($Obj -is [hashtable]) { $Obj.Keys } else { $Obj.PSObject.Properties.Name }
                foreach ($prop in $props) { Add-Node -ParentNodes $newNode.Nodes -Obj $Obj.$prop -Name $prop }
            } elseif ($Obj -is [array] -or $Obj -is [System.Collections.ICollection]) {
                $newNode = New-Object System.Windows.Forms.TreeNode("$nodeText [$($Obj.Count)]")
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
                for ($i=0; $i -lt $Obj.Count; $i++) { Add-Node -ParentNodes $newNode.Nodes -Obj $Obj[$i] -Name "[$i]" }
            } else {
                $newNode = New-Object System.Windows.Forms.TreeNode("${nodeText}: $Obj")
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
            }
        }

        try { Add-Node -ParentNodes $NodesCollection -Obj $JsonData -Name "Root" } catch {}
        if ($NodesCollection.Count -gt 0) { $NodesCollection[0].Expand() }
        $NodesCollection.Owner.EndUpdate()
    }

    $tabControlResponse = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
    }

    $tabResponse = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Response"; BorderStyle = 'None'; Padding = [System.Windows.Forms.Padding]::new(5) }
    
    # Refactored: Use a FlowLayoutPanel to match Body layout
    $responseToolsPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ 
        Dock = 'Top' #FIX: Corrected Dock property
        Padding = [System.Windows.Forms.Padding]::new(0)
        AutoSize = $true #FIX: Corrected property name
        AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        WrapContents = $false
        Margin = [System.Windows.Forms.Padding]::new(0)
    }

    $script:btnPrettifyResponse = New-Button -Text "Prettify" -Property @{ 
        Width = 100
        Height = 35
        Enabled = $false
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        try {
            if ($script:lastResponseContentType -like 'application/json*') {
                $jsonObj = $richTextResponse.Text | ConvertFrom-Json -ErrorAction Stop
                $richTextResponse.Rtf = Format-JsonAsRtf -JsonString ($jsonObj | ConvertTo-Json -Depth 10 -ErrorAction Stop) -FontSize $script:settings.ResponseFontSize
            } elseif ($script:lastResponseContentType -like 'application/xml*' -or $script:lastResponseContentType -like 'text/xml*') {
                # Use XmlWriter to properly indent the XML
                $xmlDoc = New-Object System.Xml.XmlDocument
                $xmlDoc.LoadXml($richTextResponse.Text)
                $stringWriter = New-Object System.IO.StringWriter
                $xmlWriterSettings = New-Object System.Xml.XmlWriterSettings
                $xmlWriterSettings.Indent = $true
                $xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter, $xmlWriterSettings)
                $xmlDoc.Save($xmlWriter)
                $xmlWriter.Close()
                $richTextResponse.Text = $stringWriter.ToString()
            } elseif ($script:lastResponseContentType -like 'text/html*') {
                # Use the MSHTML COM object to tidy up the HTML
                $html = New-Object -ComObject "HTMLFile"
                $html.IHTMLDocument2_write($richTextResponse.Text)
                $html.Close() # Close the document stream
                $prettyHtml = $html.documentElement.outerHTML
                $richTextResponse.Text = $prettyHtml
                # Also update the preview tab with the tidied HTML
                $webBrowserPreview.DocumentText = $prettyHtml
            }
        } catch { Write-Log "Could not prettify response content: $($_.Exception.Message)" -Level Info }
    }

    $script:btnExportResponse = New-Button -Text "Export" -Property @{ 
        Width = 100
        Height = 35
        Enabled = $false
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        if ([string]::IsNullOrWhiteSpace($richTextResponse.Text)) { return }

        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Title = "Export Response Body"

        # Suggest a file extension based on the content type
        $extension = "txt"
        $filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        if ($script:lastResponseContentType -like 'application/json*') {
            $extension = "json"; $filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        } elseif ($script:lastResponseContentType -like '*xml*') {
            $extension = "xml"; $filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*"
        } elseif ($script:lastResponseContentType -like '*html*') {
            $extension = "html"; $filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
        }
        $saveFileDialog.DefaultExt = $extension
        $saveFileDialog.Filter = $filter
        $saveFileDialog.FileName = "response.$extension"

        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $richTextResponse.Text | Set-Content -Path $saveFileDialog.FileName -Encoding UTF8 -ErrorAction Stop
                Write-Log "Response body exported to $($saveFileDialog.FileName)" -Level Info
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export response body: $($_.Exception.Message)", "Export Error", "OK", "Error")
                Write-Log "Failed to export response body: $($_.Exception.Message)" -Level Info
            }
        }
    }

    $script:btnGoToLine = New-Button -Text "Go To" -Property @{ 
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        $lineStr = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Line Number:", "Go To Line", "1")
        if ([int]::TryParse($lineStr, [ref]$null)) {
            $line = [int]$lineStr
            if ($line -gt 0 -and $line -le $richTextResponse.Lines.Length) {
                $index = $richTextResponse.GetFirstCharIndexFromLine($line - 1)
                $richTextResponse.Select($index, 0)
                $richTextResponse.ScrollToCaret()
            }
        }
    }

    $script:btnToggleWordWrap = New-Button -Text "Wrap" -Property @{ 
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        $richTextResponse.WordWrap = -not $richTextResponse.WordWrap
    }
    $toolTip.SetToolTip($script:btnToggleWordWrap, "Toggle Word Wrap")

    $script:btnFind = New-Button -Text "Find" -Property @{ 
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        $responseSearchPanel.Visible = -not $responseSearchPanel.Visible
        if ($responseSearchPanel.Visible) { $script:textSearchResponse.Focus() }
    }
    $toolTip.SetToolTip($script:btnFind, "Find text in response (Ctrl+F)")

    $script:btnExtractVariable = New-Button -Text "Extract" -Property @{
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        $responseExtractPanel.Visible = -not $responseExtractPanel.Visible
    }
    $toolTip.SetToolTip($script:btnExtractVariable, "Extract a value from the response into a variable")

    $toolTip.SetToolTip($script:btnPrettifyResponse, "Format the response content (JSON, XML, HTML).")
    $toolTip.SetToolTip($script:btnExportResponse, "Save the content of the response body to a file.")

    # Add controls to panel - Left-docked buttons first, then Right-docked
    # Add controls to panel
    $responseToolsPanel.Controls.AddRange(@($script:btnPrettifyResponse, $script:btnExportResponse, $script:btnToggleWordWrap, $script:btnGoToLine, $script:btnFind, $script:btnExtractVariable))
    
    # Refactored: Use a Panel with Docking strategy consistent with main layout
    $responseSearchPanel = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Top'
        Height = 45
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
        Visible = $false
        BackColor = $script:Theme.GroupBackground
    }

    $script:textSearchResponse = New-TextBox -Property @{ 
        Dock = 'Fill'
        Text = "Find..." 
        ForeColor = [System.Drawing.Color]::Gray 
    }
    
    $script:textSearchResponse.Add_Enter({ 
        if ($script:textSearchResponse.Text -eq "Find...") { 
            $script:textSearchResponse.Text = ""; 
            $script:textSearchResponse.ForeColor = [System.Drawing.Color]::Black 
        } 
    })
    
    $script:textSearchResponse.Add_Leave({ 
        if ([string]::IsNullOrWhiteSpace($script:textSearchResponse.Text)) { 
            $script:textSearchResponse.Text = "Find..."; 
            $script:textSearchResponse.ForeColor = [System.Drawing.Color]::Gray 
            $script:labelSearchStatus.Text = ""
        } 
    })

    $script:btnSearchPrev = New-Button -Text "<" -Property @{ 
        Dock = 'Right'
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0) 
    }
    $toolTip.SetToolTip($script:btnSearchPrev, "Find Previous")
    $script:btnSearchNext = New-Button -Text ">" -Property @{ 
        Dock = 'Right'
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) 
    }
    $toolTip.SetToolTip($script:btnSearchNext, "Find Next")
    $script:checkSearchMatchCase = New-Object System.Windows.Forms.CheckBox -Property @{ 
        Text = "Aa"
        Dock = 'Right'
        Appearance = 'Button'
        AutoSize = $false 
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0)
    }
    $toolTip.SetToolTip($script:checkSearchMatchCase, "Match Case")

    $script:checkSearchWholeWord = New-Object System.Windows.Forms.CheckBox -Property @{ 
        Text = "WW"
        Dock = 'Right'
        Appearance = 'Button'
        AutoSize = $false 
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0)
    }
    $toolTip.SetToolTip($script:checkSearchWholeWord, "Match Whole Word Only")

    $script:labelSearchStatus = New-Label -Text "" -Property @{ 
        Dock = 'Right'
        AutoSize = $true 
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(10, 0, 10, 0)
    }

    function Get-ResponseSearchMatches {
        param([string]$SearchText)
        if ([string]::IsNullOrWhiteSpace($SearchText) -or $SearchText -eq "Find...") { return @() }

        $escaped = [regex]::Escape($SearchText)
        if ($script:checkSearchWholeWord.Checked) {
            $wordChars = "A-Za-z0-9_-"
            $pattern = "(?<![$wordChars])$escaped(?![$wordChars])"
        } else {
            $pattern = $escaped
        }

        $options = [System.Text.RegularExpressions.RegexOptions]::None
        if (-not $script:checkSearchMatchCase.Checked) {
            $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        }

        return @([regex]::Matches($richTextResponse.Text, $pattern, $options))
    }

    function Apply-ResponseSearchHighlights {
        param(
            [array]$Matches,
            [int]$CurrentIndex
        )
        # Preserve current selection
        $currentSelStart = $richTextResponse.SelectionStart
        $currentSelLength = $richTextResponse.SelectionLength

        $richTextResponse.SuspendLayout()
        # Clear previous highlights
        $richTextResponse.SelectAll()
        $richTextResponse.SelectionBackColor = [System.Drawing.Color]::Empty
        $richTextResponse.DeselectAll()

        if ($Matches -and $Matches.Count -gt 0) {
            for ($i = 0; $i -lt $Matches.Count; $i++) {
                $m = $Matches[$i]
                $richTextResponse.Select($m.Index, $m.Length)
                $richTextResponse.SelectionBackColor = if ($i -eq $CurrentIndex) { [System.Drawing.Color]::Orange } else { [System.Drawing.Color]::Yellow }
            }
        }

        # Restore selection
        $richTextResponse.Select($currentSelStart, $currentSelLength)
        $richTextResponse.ResumeLayout()
    }

    $searchHandler = {
        $searchText = $script:textSearchResponse.Text

        if ($searchText -ne "Find..." -and -not [string]::IsNullOrEmpty($searchText)) {
            $matches = Get-ResponseSearchMatches -SearchText $searchText
            $script:responseSearchMatches = $matches
            $script:responseSearchCurrentIndex = if ($matches.Count -gt 0) { 0 } else { -1 }

            if ($matches.Count -gt 0) {
                Apply-ResponseSearchHighlights -Matches $matches -CurrentIndex $script:responseSearchCurrentIndex

                $script:labelSearchStatus.Text = "$($matches.Count) Found"
                $script:labelSearchStatus.ForeColor = [System.Drawing.Color]::Green
                # Scroll to the first match
                $richTextResponse.Select($matches[0].Index, 0)
                $richTextResponse.ScrollToCaret()
            } else {
                $script:labelSearchStatus.Text = "0 Found"
                $script:labelSearchStatus.ForeColor = [System.Drawing.Color]::Red
                Apply-ResponseSearchHighlights -Matches @() -CurrentIndex -1
            }
        } else {
            $script:labelSearchStatus.Text = ""
            Apply-ResponseSearchHighlights -Matches @() -CurrentIndex -1
        }
        $script:textSearchResponse.Focus()
    }

    $script:textSearchResponse.Add_TextChanged($searchHandler)
    $script:checkSearchWholeWord.Add_CheckedChanged($searchHandler)
    $script:checkSearchMatchCase.Add_CheckedChanged($searchHandler)

    # Next/Prev Logic
    $findNextPrev = {
        param($direction) # 1 for Next, -1 for Prev
        $searchText = $script:textSearchResponse.Text
        if ($searchText -eq "Find..." -or [string]::IsNullOrEmpty($searchText)) { return }

        if (-not $script:responseSearchMatches -or $script:responseSearchMatches.Count -eq 0) {
            $script:responseSearchMatches = Get-ResponseSearchMatches -SearchText $searchText
        }

        $matches = $script:responseSearchMatches
        if ($matches.Count -eq 0) { return }

        $cursor = $richTextResponse.SelectionStart
        if ($direction -eq 1) {
            $cursor += [Math]::Max(1, $richTextResponse.SelectionLength)
        }

        if ($direction -eq 1) {
            $nextMatch = $matches | Where-Object { $_.Index -ge $cursor } | Select-Object -First 1
            if (-not $nextMatch) { $nextMatch = $matches[0] }
            $richTextResponse.Select($nextMatch.Index, $nextMatch.Length)
            $script:responseSearchCurrentIndex = [array]::IndexOf($matches, $nextMatch)
        } else {
            $prevMatch = $matches | Where-Object { $_.Index -lt $cursor } | Select-Object -Last 1
            if (-not $prevMatch) { $prevMatch = $matches[$matches.Count - 1] }
            $richTextResponse.Select($prevMatch.Index, $prevMatch.Length)
            $script:responseSearchCurrentIndex = [array]::IndexOf($matches, $prevMatch)
        }

        Apply-ResponseSearchHighlights -Matches $matches -CurrentIndex $script:responseSearchCurrentIndex
        $richTextResponse.ScrollToCaret()
        $richTextResponse.Focus() # Focus RTB to show selection
    }
    $script:btnSearchNext.Add_Click({ & $findNextPrev 1 })
    $script:btnSearchPrev.Add_Click({ & $findNextPrev -1 })

    $script:btnCloseSearch = New-Button -Text "X" -Property @{ 
        Dock = 'Right'
        Width = 35 
        FlatStyle = [System.Windows.Forms.FlatStyle]::Flat 
        ForeColor = [System.Drawing.Color]::Red 
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0)
    } -OnClick {
        $responseSearchPanel.Visible = $false
        Apply-ResponseSearchHighlights -Matches @() -CurrentIndex -1
    }
    $toolTip.SetToolTip($script:btnCloseSearch, "Close Find Bar")

    # Add controls to panel - Fill first, then Right-docked controls in order
    $responseSearchPanel.Controls.AddRange(@($script:textSearchResponse, $script:labelSearchStatus, $script:checkSearchWholeWord, $script:checkSearchMatchCase, $script:btnSearchNext, $script:btnSearchPrev, $script:btnCloseSearch))

    # --- Response Extract Panel ---
    $responseExtractPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Top'
        AutoSize = $true
        AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
        Visible = $false
        BackColor = $script:Theme.GroupBackground
        WrapContents = $true
    }

    $lblVarName = New-Label -Text "Var:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:textExtractVarName = New-TextBox -Property @{ Width = 120; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $lblVarBrowse = New-Label -Text "Pick:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractVarBrowser = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 140; Margin = [System.Windows.Forms.Padding]::new(0,3,5,0) }
    $script:btnRefreshVarBrowser = New-Button -Text "Refresh" -Style 'Secondary' -Property @{ Width = 70; Height = 26; Margin = [System.Windows.Forms.Padding]::new(0,2,10,0) } -OnClick {
        if ($null -ne $updateExtractVarList) { & $updateExtractVarList }
    }
    $toolTip.SetToolTip($script:btnRefreshVarBrowser, "Refresh variable list")

    $lblScope = New-Label -Text "Scope:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractScope = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 120; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $script:comboExtractScope.Items.AddRange(@("Global", "Collection", "Environment"))
    $script:comboExtractScope.SelectedIndex = 0

    $lblSource = New-Label -Text "Source:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractSource = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 90; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $script:comboExtractSource.Items.AddRange(@("Body", "Headers"))
    $script:comboExtractSource.SelectedIndex = 0

    $lblMode = New-Label -Text "Mode:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractMode = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 110; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $script:comboExtractMode.Items.AddRange(@("JSON Path", "Regex"))
    $script:comboExtractMode.SelectedIndex = 0

    $lblPath = New-Label -Text "Path/Regex:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:textExtractPath = New-TextBox -Property @{ Width = 220; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }

    $updateExtractVarList = {
        $vars = @()
        switch ($script:comboExtractScope.SelectedItem) {
            "Global" {
                if ($script:globals) { $vars = $script:globals.Keys }
            }
            "Collection" {
                if ($script:activeCollectionNode -and $script:activeCollectionNode.Tag.Type -eq "Collection") {
                    if (-not ($script:activeCollectionNode.Tag.PSObject.Properties.Name -contains 'Variables')) {
                        $script:activeCollectionNode.Tag | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{}
                    }
                    if ($null -ne $script:activeCollectionNode.Tag.Variables) { $vars = $script:activeCollectionNode.Tag.Variables.Keys }
                }
            }
            "Environment" {
                if ($script:activeEnvironment -ne "No Environment" -and $script:environments.ContainsKey($script:activeEnvironment)) {
                    $envData = $script:environments[$script:activeEnvironment]
                    if ($envData -is [hashtable] -and $envData.ContainsKey('Variables')) { $vars = $envData['Variables'].Keys }
                    elseif ($envData.PSObject.Properties.Name -contains 'Variables') { $vars = $envData.Variables.Keys }
                }
            }
        }
        $script:comboExtractVarBrowser.Items.Clear()
        [void]$script:comboExtractVarBrowser.Items.Add("")
        foreach ($k in ($vars | Sort-Object)) { [void]$script:comboExtractVarBrowser.Items.Add($k) }
        $script:comboExtractVarBrowser.SelectedIndex = 0
        $script:comboExtractVarBrowser.Enabled = ($vars.Count -gt 0)
    }

    $script:comboExtractScope.Add_SelectedIndexChanged($updateExtractVarList)
    $script:comboExtractVarBrowser.Add_SelectedIndexChanged({
        $selected = $script:comboExtractVarBrowser.SelectedItem
        if ($selected -and $selected -ne "") { $script:textExtractVarName.Text = $selected }
    })
    & $updateExtractVarList

    $script:btnExtractSave = New-Button -Text "Extract & Save" -Style 'Primary' -Property @{ Width = 140; Height = 30; Margin = [System.Windows.Forms.Padding]::new(0,2,10,0) } -OnClick {
        $varName = $script:textExtractVarName.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($varName)) {
            $script:labelExtractStatus.Text = "Variable name is required."
            $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
            return
        }

        $source = $script:comboExtractSource.SelectedItem
        $mode = $script:comboExtractMode.SelectedItem
        $rawText = if ($source -eq "Headers") { $script:lastResponseHeadersText } else { $script:lastResponseText }
        if ([string]::IsNullOrWhiteSpace($rawText)) {
            $script:labelExtractStatus.Text = "No response content to extract."
            $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
            return
        }

        $extracted = $null
        if ($mode -eq "JSON Path") {
            if ($source -ne "Body") {
                $script:labelExtractStatus.Text = "JSON Path only supports Body source."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
            $path = $script:textExtractPath.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($path)) {
                $script:labelExtractStatus.Text = "JSON path is required."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
            try {
                $jsonObj = $rawText | ConvertFrom-Json -ErrorAction Stop
                $value = Get-JsonPathValue -JsonObject $jsonObj -Path $path
                if ($null -eq $value) {
                    $script:labelExtractStatus.Text = "Path not found."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                $extracted = if ($value -is [string]) { $value } else { $value | ConvertTo-Json -Depth 10 }
            } catch {
                $script:labelExtractStatus.Text = "Invalid JSON or path."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
        } else {
            $pattern = $script:textExtractPath.Text
            if ([string]::IsNullOrWhiteSpace($pattern)) {
                $script:labelExtractStatus.Text = "Regex pattern is required."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
            try {
                $m = [regex]::Match($rawText, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                if (-not $m.Success) {
                    $script:labelExtractStatus.Text = "No regex match."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                if ($m.Groups.Count -gt 1 -and $m.Groups[1].Value) { $extracted = $m.Groups[1].Value } else { $extracted = $m.Value }
            } catch {
                $script:labelExtractStatus.Text = "Invalid regex."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
        }

        switch ($script:comboExtractScope.SelectedItem) {
            "Global" {
                $script:globals[$varName] = $extracted
                Save-Globals
            }
            "Collection" {
                if (-not $script:activeCollectionNode -or $script:activeCollectionNode.Tag.Type -ne "Collection") {
                    $script:labelExtractStatus.Text = "No active collection selected."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                if (-not ($script:activeCollectionNode.Tag.PSObject.Properties.Name -contains 'Variables')) {
                    $script:activeCollectionNode.Tag | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{}
                }
                if ($null -eq $script:activeCollectionNode.Tag.Variables) { $script:activeCollectionNode.Tag.Variables = @{} }
                $script:activeCollectionNode.Tag.Variables[$varName] = $extracted
                $script:activeCollectionVariables = $script:activeCollectionNode.Tag.Variables
                Save-Collections
            }
            "Environment" {
                if ($script:activeEnvironment -eq "No Environment" -or -not $script:environments.ContainsKey($script:activeEnvironment)) {
                    $script:labelExtractStatus.Text = "No active environment selected."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                $envData = $script:environments[$script:activeEnvironment]
                if ($envData -is [hashtable]) {
                    if (-not $envData.ContainsKey('Variables')) { $envData['Variables'] = @{} }
                    if ($null -eq $envData['Variables']) { $envData['Variables'] = @{} }
                    $envData['Variables'][$varName] = $extracted
                    Save-Environments
                    $script:labelExtractStatus.Text = "Saved '$varName' to Environment."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Green
                    return
                } else {
                    if (-not ($envData.PSObject.Properties.Name -contains 'Variables')) { $envData | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{} }
                    if ($null -eq $envData.Variables) { $envData.Variables = @{} }
                    $envData.Variables[$varName] = $extracted
                }
                Save-Environments
            }
        }

        $script:labelExtractStatus.Text = "Saved '$varName' to $($script:comboExtractScope.SelectedItem)."
        $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Green
        & $updateExtractVarList
        if ($script:comboExtractVarBrowser.Items.Contains($varName)) { $script:comboExtractVarBrowser.SelectedItem = $varName }
    }

    $script:labelExtractStatus = New-Label -Text "" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,0,0) }

    $responseExtractPanel.Controls.AddRange(@(
        $lblVarName, $script:textExtractVarName,
        $lblVarBrowse, $script:comboExtractVarBrowser, $script:btnRefreshVarBrowser,
        $lblScope, $script:comboExtractScope,
        $lblSource, $script:comboExtractSource,
        $lblMode, $script:comboExtractMode,
        $lblPath, $script:textExtractPath,
        $script:btnExtractSave, $script:labelExtractStatus
    ))

    $richTextResponse = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; HideSelection = $false; DetectUrls = $true; BorderStyle = 'None' }
    $richTextResponse.Add_KeyDown({
        param($sender, $e)
        if ($e.Control -and $e.KeyCode -eq 'F') {
            $script:btnFind.PerformClick()
            $e.SuppressKeyPress = $true
        }
    })
    $richTextResponse.Add_LinkClicked({
        param($sender, $e)
        $linkText = $e.LinkText
        if ($linkText -match "^file:") {
            try {
                $uri = New-Object System.Uri $linkText
                $localPath = $uri.LocalPath
                if (Test-Path $localPath) {
                    Start-Process "explorer.exe" -ArgumentList "/select,`"$localPath`""
                }
            } catch { Write-Log "Failed to open file link: $($_.Exception.Message)" -Level Info }
        } else {
            try { Start-Process $linkText } catch { }
        }
    })
    $richTextResponse.ContextMenuStrip = New-CopyContextMenu -ParentControl $richTextResponse

    $responseLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 4
        Margin = [System.Windows.Forms.Padding]::new(0)
        Padding = [System.Windows.Forms.Padding]::new(5, 0, 5, 5)
    }
    $responseLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $responseLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $responseLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $responseLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $responseLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $responseLayout.Controls.Add($responseToolsPanel, 0, 0)
    $responseLayout.Controls.Add($responseSearchPanel, 0, 1)
    $responseLayout.Controls.Add($responseExtractPanel, 0, 2)
    $responseLayout.Controls.Add($richTextResponse, 0, 3)
    $tabResponse.Controls.Add($responseLayout)

    $tabHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Response Headers" }
    $richTextResponseHeaders = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; DetectUrls = $true; BorderStyle = 'None' }
    $richTextResponseHeaders.ContextMenuStrip = New-CopyContextMenu -ParentControl $richTextResponseHeaders
    $richTextResponseHeaders.Dock = [System.Windows.Forms.DockStyle]::Fill
    $tabHeaders.Controls.Add($richTextResponseHeaders)

    $tabJsonTree = New-Object System.Windows.Forms.TabPage -Property @{ Text = "JSON Tree" }
    
    # --- JSON Tree Search Panel ---
    $jsonTreeSearchPanel = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Top'
        Height = 30
        Padding = [System.Windows.Forms.Padding]::new(2)
        BackColor = $script:Theme.GroupBackground
    }

    $textSearchJsonTree = New-TextBox -Property @{ 
        Dock = 'Fill'
        Text = "Search JSON..." 
        ForeColor = [System.Drawing.Color]::Gray 
    }
    
    $textSearchJsonTree.Add_Enter({ 
        if ($textSearchJsonTree.Text -eq "Search JSON...") { 
            $textSearchJsonTree.Text = ""; 
            $textSearchJsonTree.ForeColor = [System.Drawing.Color]::Black 
        } 
    })
    
    $textSearchJsonTree.Add_Leave({ 
        if ([string]::IsNullOrWhiteSpace($textSearchJsonTree.Text)) { 
            $textSearchJsonTree.Text = "Search JSON..."; 
            $textSearchJsonTree.ForeColor = [System.Drawing.Color]::Gray 
            $lblJsonTreeStatus.Text = ""
        } 
    })

    $lblJsonTreeStatus = New-Label -Text "" -Property @{ Dock = 'Right'; AutoSize = $true; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(5, 0, 5, 0) }

    $script:jsonTreeMatches = @()
    $script:jsonTreeCurrentIndex = -1

    $navigateJsonTreeSearch = {
        param($direction)
        if ($script:jsonTreeMatches.Count -eq 0) { return }
        $script:jsonTreeCurrentIndex += $direction
        if ($script:jsonTreeCurrentIndex -ge $script:jsonTreeMatches.Count) { $script:jsonTreeCurrentIndex = 0 }
        if ($script:jsonTreeCurrentIndex -lt 0) { $script:jsonTreeCurrentIndex = $script:jsonTreeMatches.Count - 1 }
        $node = $script:jsonTreeMatches[$script:jsonTreeCurrentIndex]
        $treeViewJson.SelectedNode = $node
        $node.EnsureVisible()
        $treeViewJson.Focus()
        $lblJsonTreeStatus.Text = "$($script:jsonTreeCurrentIndex + 1)/$($script:jsonTreeMatches.Count)"
    }

    $btnJsonTreeNext = New-Button -Text ">" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { & $navigateJsonTreeSearch 1 }
    $btnJsonTreePrev = New-Button -Text "<" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { & $navigateJsonTreeSearch -1 }

    $btnJsonTreeCollapse = New-Button -Text "-" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { $treeViewJson.CollapseAll() }
    $toolTip.SetToolTip($btnJsonTreeCollapse, "Collapse All")
    
    $btnJsonTreeExpand = New-Button -Text "+" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { $treeViewJson.ExpandAll() }
    $toolTip.SetToolTip($btnJsonTreeExpand, "Expand All")

    $performJsonTreeSearch = {
        $term = $textSearchJsonTree.Text
        if ($term -eq "Search JSON..." -or [string]::IsNullOrWhiteSpace($term)) { return }
        $matches = New-Object System.Collections.ArrayList
        $recurse = {
            param($nodes)
            foreach ($node in $nodes) {
                if ($node.Text -like "*$term*") { [void]$matches.Add($node) }
                if ($node.Nodes.Count -gt 0) { & $recurse -nodes $node.Nodes }
            }
        }
        & $recurse -nodes $treeViewJson.Nodes
        $script:jsonTreeMatches = $matches
        $script:jsonTreeCurrentIndex = -1
        if ($matches.Count -gt 0) {
            $script:jsonTreeCurrentIndex = 0
            $node = $matches[0]
            $treeViewJson.SelectedNode = $node
            $node.EnsureVisible()
            $treeViewJson.Focus()
            $lblJsonTreeStatus.Text = "1/$($matches.Count)"; $lblJsonTreeStatus.ForeColor = [System.Drawing.Color]::Green
        } else { $lblJsonTreeStatus.Text = "0 found"; $lblJsonTreeStatus.ForeColor = [System.Drawing.Color]::Red }
    }

    $textSearchJsonTree.Add_KeyDown({ param($sender, $e) if ($e.KeyCode -eq 'Enter') { & $performJsonTreeSearch; $e.SuppressKeyPress = $true } })
    $jsonTreeSearchPanel.Controls.AddRange(@($textSearchJsonTree, $lblJsonTreeStatus, $btnJsonTreeNext, $btnJsonTreePrev, $btnJsonTreeExpand, $btnJsonTreeCollapse))

    $treeViewJson = New-Object System.Windows.Forms.TreeView -Property @{ Dock = 'Fill'; BorderStyle = 'None'; HideSelection = $false }
    
    $jsonContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $itemCopyKey = $jsonContextMenu.Items.Add("Copy Key")
    $itemCopyKey.Add_Click({
        if ($treeViewJson.SelectedNode -and $treeViewJson.SelectedNode.Tag) {
            [System.Windows.Forms.Clipboard]::SetText([string]$treeViewJson.SelectedNode.Tag.Key)
        }
    })
    $itemCopyValue = $jsonContextMenu.Items.Add("Copy Value")
    $itemCopyValue.Add_Click({
        if ($treeViewJson.SelectedNode -and $treeViewJson.SelectedNode.Tag) {
            $val = $treeViewJson.SelectedNode.Tag.Value
            $text = if ($val -is [string] -or $val -is [ValueType]) { "$val" } else { $val | ConvertTo-Json -Depth 10 -Compress }
            if ($text) { [System.Windows.Forms.Clipboard]::SetText($text) }
        }
    })
    $treeViewJson.ContextMenuStrip = $jsonContextMenu
    $treeViewJson.Add_NodeMouseClick({ param($s,$e) if ($e.Button -eq 'Right') { $treeViewJson.SelectedNode = $e.Node } })
    
    $tabJsonTree.Controls.Add($treeViewJson)
    $tabJsonTree.Controls.Add($jsonTreeSearchPanel)

    $tabCode = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Code Snippets"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $panelCodeTools = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true; AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; Padding = [System.Windows.Forms.Padding]::new(3) }
    $script:comboCodeLanguage = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 120; DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Margin = [System.Windows.Forms.Padding]::new(3) }
    $script:comboCodeLanguage.Items.AddRange(@("cURL", "PowerShell", "Python", "JavaScript", "C#"))
    $script:comboCodeLanguage.SelectedIndex = 0
    $panelCodeTools.Controls.Add($script:comboCodeLanguage)
    
    $richTextCode = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; BorderStyle = 'None' }
    $richTextCode.ContextMenuStrip = New-CopyContextMenu -ParentControl $richTextCode
    $codeLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 2
        Margin = [System.Windows.Forms.Padding]::new(0)
        Padding = [System.Windows.Forms.Padding]::new(0)
    }
    $codeLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $codeLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $codeLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $codeLayout.Controls.Add($panelCodeTools, 0, 0)
    $codeLayout.Controls.Add($richTextCode, 0, 1)
    $tabCode.Controls.Add($codeLayout)
    # --- Console Tab ---
    $tabConsole = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Console" }
    $consoleSplit = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock = 'Fill'; Orientation = 'Horizontal'; SplitterDistance = 200 }
    
    # Console Output (Top)
    $defaultLang = if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { "PowerShell" }
    $script:consoleOutput = New-RichTextBox -ReadOnly $true -Property @{ Dock = 'Fill'; BackColor = 'Black'; ForeColor = 'White'; Font = New-Object System.Drawing.Font("Courier New", 9); Text = "Welcome to API Tester Console.`nDefault language: $defaultLang.`nPrefix commands with 'python:', 'js:', 'php:', 'ruby:', 'go:', 'bat:', 'bash:' to switch languages.`nExample: python: print('Hello')`n`n"; BorderStyle = 'None' }
    $script:consoleOutput.ContextMenuStrip = New-CopyContextMenu -ParentControl $script:consoleOutput
    
    # Console Input (Bottom)
    $consoleInputPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill' } #FIX: Corrected Panel creation
    $consoleToolbar = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true; AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; Padding = [System.Windows.Forms.Padding]::new(3) }
    
    $script:consolePlaceholder = "Enter command here... (Ctrl+Enter or Shift+Enter to run)"

    $btnRunConsole = New-Button -Text "Run" -Property @{ Dock = 'Left'; Width = 60; Margin = [System.Windows.Forms.Padding]::new(5,0,0,0) } -OnClick {
        $code = $script:consoleInput.Text
        if ([string]::IsNullOrWhiteSpace($code) -or $code -eq $script:consolePlaceholder) { return }
        
        # Language Detection and Parsing
        $lang = if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { "PowerShell" }
        $scriptToRun = $code
        
        if ($code -match '^(python|py):\s*(.*)') { $lang = "Python"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(js|node|javascript):\s*(.*)') { $lang = "JavaScript (Node.js)"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(php):\s*(.*)') { $lang = "PHP"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(ruby|rb):\s*(.*)') { $lang = "Ruby"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(go):\s*(.*)') { $lang = "Go"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(bat|cmd|batch):\s*(.*)') { $lang = "Batch"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(bash|sh):\s*(.*)') { $lang = "Bash"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(ps|pwsh|powershell):\s*(.*)') { $lang = "PowerShell"; $scriptToRun = $matches[2] }

        # Echo Input
        $script:consoleOutput.SelectionColor = [System.Drawing.Color]::LightGray
        $script:consoleOutput.AppendText("> $code`n")
        $script:consoleOutput.SelectionColor = [System.Drawing.Color]::White
        $script:consoleOutput.ScrollToCaret()
        
        try {
            if ($lang -eq "PowerShell") {
                # Run in the current session to allow manipulation of form variables
                $output = Invoke-Expression $scriptToRun | Out-String
                $script:consoleOutput.AppendText($output)
            } else {
                # External execution
                $fileName = [System.IO.Path]::GetTempFileName()
                $argsList = @()
                $exe = ""
                
                switch ($lang) {
                    "JavaScript (Node.js)" { $exe = "node"; $fileName += ".js"; $argsList = @($fileName) }
                    "Python"  { $exe = "python"; $fileName += ".py"; $argsList = @($fileName) }
                    "PHP"     { $exe = "php"; $fileName += ".php"; $argsList = @($fileName) }
                    "Ruby"    { $exe = "ruby"; $fileName += ".rb"; $argsList = @($fileName) }
                    "Go"      { $exe = "go"; $fileName += ".go"; $argsList = @("run", $fileName) }
                    "Batch"   { $exe = "cmd"; $fileName += ".bat"; $argsList = @("/c", $fileName) }
                    "Bash"    { $exe = "bash"; $fileName += ".sh"; $argsList = @($fileName) }
                }
                
                $scriptToRun | Set-Content -Path $fileName -Encoding UTF8
                
                $processInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processInfo.FileName = $exe
                $processInfo.Arguments = $argsList -join " "
                $processInfo.RedirectStandardOutput = $true
                $processInfo.RedirectStandardError = $true
                $processInfo.UseShellExecute = $false
                $processInfo.CreateNoWindow = $true
                
                $process = [System.Diagnostics.Process]::Start($processInfo)
                $process.WaitForExit()
                
                $stdOut = $process.StandardOutput.ReadToEnd()
                $stdErr = $process.StandardError.ReadToEnd()
                
                if ($stdOut) { $script:consoleOutput.AppendText($stdOut) }
                if ($stdErr) { $script:consoleOutput.SelectionColor = [System.Drawing.Color]::Red; $script:consoleOutput.AppendText($stdErr); $script:consoleOutput.SelectionColor = [System.Drawing.Color]::White }
                
                Remove-Item $fileName -ErrorAction SilentlyContinue
            }
        } catch {
            $script:consoleOutput.SelectionColor = [System.Drawing.Color]::Red
            $script:consoleOutput.AppendText("Error: $($_.Exception.Message)`n")
            $script:consoleOutput.SelectionColor = [System.Drawing.Color]::White
        }
        $script:consoleOutput.AppendText("`n")
        $script:consoleOutput.ScrollToCaret()
    }
    
    $btnClearConsole = New-Button -Text "Clear" -Property @{ Dock = 'Left'; Width = 60; Margin = [System.Windows.Forms.Padding]::new(5,0,0,0) } -OnClick { $script:consoleOutput.Clear() }
    
    $consoleToolbar.Controls.AddRange(@($btnClearConsole, $btnRunConsole))
    
    $script:consoleInput = New-RichTextBox -Property @{ Dock = 'Fill'; BackColor = 'Black'; ForeColor = 'Gray'; Font = New-Object System.Drawing.Font("Courier New", 9); AcceptsTab = $true; Text = $script:consolePlaceholder; BorderStyle = 'None' }
    
    $script:consoleInput.Add_Enter({
        if ($script:consoleInput.Text -eq $script:consolePlaceholder) {
            $script:consoleInput.Text = ""
            $script:consoleInput.ForeColor = [System.Drawing.Color]::White
        }
    })
    
    $script:consoleInput.Add_Leave({
        if ([string]::IsNullOrWhiteSpace($script:consoleInput.Text)) {
            $script:consoleInput.Text = $script:consolePlaceholder
            $script:consoleInput.ForeColor = [System.Drawing.Color]::Gray
        }
    })

    $script:consoleInput.Add_KeyDown({
        param($sender, $e)
        if (($e.Control -or $e.Shift) -and $e.KeyCode -eq 'Enter') {
            $btnRunConsole.PerformClick()
            $e.SuppressKeyPress = $true
        }
    })

    # Basic Syntax Highlighting for Console Input
    $script:isHighlighting = $false
    $script:consoleInput.Add_TextChanged({
        if ($script:isHighlighting) { return }
        if ($script:consoleInput.Text -eq $script:consolePlaceholder) { return }
        $script:isHighlighting = $true
        $rtb = $script:consoleInput
        $rtb.SuspendLayout()
        $selStart = $rtb.SelectionStart
        $selLength = $rtb.SelectionLength
        
        $rtb.SelectAll()
        $rtb.SelectionColor = [System.Drawing.Color]::White
        
        $text = $rtb.Text
        # Keywords (Blue)
        $keywords = "\b(if|else|elseif|for|foreach|return|function|var|let|const|try|catch|switch|case|while|do|class|import|from|def|end|param|in|echo|print|write-host)\b"
        [regex]::Matches($text, $keywords, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | ForEach-Object {
            $rtb.Select($_.Index, $_.Length); $rtb.SelectionColor = [System.Drawing.Color]::LightSkyBlue
        }
        # Strings (Orange)
        [regex]::Matches($text, "(['`"])(?:\\\1|.)*?\1") | ForEach-Object {
            $rtb.Select($_.Index, $_.Length); $rtb.SelectionColor = [System.Drawing.Color]::LightSalmon
        }

        $rtb.Select($selStart, $selLength)
        $rtb.SelectionColor = [System.Drawing.Color]::White
        $rtb.ResumeLayout()
        $script:isHighlighting = $false
    })
    
    $consoleInputPanel.Controls.Add($script:consoleInput)
    $consoleInputPanel.Controls.Add($consoleToolbar)
    $consoleSplit.Panel1.Controls.Add($script:consoleOutput)
    $consoleSplit.Panel2.Controls.Add($consoleInputPanel)
    $tabConsole.Controls.Add($consoleSplit)

    $script:comboCodeLanguage.Add_SelectedIndexChanged({
        if ($script:lastRequestState) {
            $richTextCode.Text = Generate-CodeSnippet -RequestItem $script:lastRequestState -Language $script:comboCodeLanguage.SelectedItem
        }
    })

    $tabPreview = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Preview" }
    $webBrowserPreview = New-Object System.Windows.Forms.WebBrowser -Property @{ Dock = 'Fill'; Visible = $false }
    $pictureBoxPreview = New-Object System.Windows.Forms.PictureBox -Property @{ Dock = 'Fill'; SizeMode = 'Zoom'; Visible = $false }
    $tabPreview.Controls.AddRange(@($webBrowserPreview, $pictureBoxPreview))
    # Visibility is managed during response processing

    $tabTestResults = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Test Results" }
    $script:richTextTestResults = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; BorderStyle = 'None' }
    $script:richTextTestResults.ContextMenuStrip = New-CopyContextMenu -ParentControl $script:richTextTestResults
    $tabTestResults.Controls.Add($script:richTextTestResults)

    $groupResponse.Controls.Add($tabControlResponse)

    # GroupBox for the request history list.
    $groupHistory = New-Object System.Windows.Forms.GroupBox -Property @{
        Dock     = [System.Windows.Forms.DockStyle]::Fill
        Padding  = [System.Windows.Forms.Padding]::new(3, 3, 3, 3) # Add padding
        Text     = "Collections & History"
        BackColor = $script:Theme.GroupBackground
    }

    # Populates the history listbox from the $script:history array.
    function Populate-HistoryList { # Renamed from Populate-HistoryTab
        param(
            [string]$TextFilter,
            [string]$EnvironmentFilter
        )

        $listHistory.Items.Clear()
        $listHistory.DisplayMember = "Display" # Use the 'Display' property for the text
        $itemsToShow = $script:history | Where-Object { $_ -ne $null }

        if (-not [string]::IsNullOrWhiteSpace($TextFilter)) {
            $itemsToShow = $itemsToShow | Where-Object { $_.Method -like "*$TextFilter*" -or $_.Url -like "*$TextFilter*" }
        }

        if ($EnvironmentFilter -and $EnvironmentFilter -ne "All Environments") {
            $itemsToShow = $itemsToShow | Where-Object { $_.Environment -eq $EnvironmentFilter }
        }

        foreach ($item in $itemsToShow) {
            if ($item.Timestamp -and $item.Method -and $item.Url) {
                $tsStr = if ($item.Timestamp -is [PSCustomObject]) { $item.Timestamp.DateTime } else { $item.Timestamp }
                $ts = [DateTime]::MinValue
                $parsed = [DateTime]::TryParse($tsStr, [ref]$ts)
                if (-not $parsed) {
                    $parsed = [DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$ts)
                }
                if (-not $parsed) {
                    $parsed = [DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::GetCultureInfo("en-US"), [System.Globalization.DateTimeStyles]::None, [ref]$ts)
                }

                if ($parsed) {
                    $displayString = "$($ts.ToString('HH:mm:ss')) | $($item.Method) | $($item.Url)"
                    $listItem = [PSCustomObject]@{ Display = $displayString; Value = $item }
                    $listHistory.Items.Add($listItem)
                } else {
                    $displayString = "??:??:?? | $($item.Method) | $($item.Url)"
                    $listItem = [PSCustomObject]@{ Display = $displayString; Value = $item }
                    $listHistory.Items.Add($listItem)
                }
            }
        }
    }

    function Populate-HistoryEnvironmentFilter {
        $currentSelection = $comboHistoryEnvFilter.SelectedItem
        $comboHistoryEnvFilter.Items.Clear()
        $comboHistoryEnvFilter.Items.Add("All Environments")
        $script:environments.Keys | Sort-Object | ForEach-Object { $comboHistoryEnvFilter.Items.Add($_) }
        if ($currentSelection -and $comboHistoryEnvFilter.Items.Contains($currentSelection)) { $comboHistoryEnvFilter.SelectedItem = $currentSelection } else { $comboHistoryEnvFilter.SelectedItem = "All Environments" }
    }

    # Recursively populates the TreeView with collections, folders, and requests.
    function Populate-CollectionsTreeView {
        param ([System.Windows.Forms.TreeNodeCollection]$nodes, [array]$items)

        $nodes.Clear()
        foreach ($item in $items) {
            $newNode = New-Object System.Windows.Forms.TreeNode($item.Name)
            $newNode.Tag = $item # Store the full object
            if ($item.Type -eq "Collection") {
                $newNode.ImageIndex = 0
                $newNode.SelectedImageIndex = 0
            } elseif ($item.Type -eq "Folder") {
                $newNode.ImageIndex = 1
                $newNode.SelectedImageIndex = 1
            } else { # Request
                $newNode.ImageIndex = 2
                $newNode.SelectedImageIndex = 2
            }
        $nodes.Add($newNode) | Out-Null # Add node to TreeView
            if ($item.Items) { Populate-CollectionsTreeView -nodes $newNode.Nodes -items $item.Items }
        }
    }

    function Get-CollectionNodeFromChild {
        param([System.Windows.Forms.TreeNode]$node)
        $current = $node
        while ($current -and $current.Tag -and $current.Tag.Type -ne "Collection") {
            $current = $current.Parent
        }
        return $current
    }
    $historyPanelContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $dockUndockMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Undock Panel", $null, {
        $script:isHistoryUndocked = -not $script:isHistoryUndocked
        if ($script:isHistoryUndocked) {
            $dockUndockMenuItem.Text = "Dock Panel"
        } else {
            $dockUndockMenuItem.Text = "Undock Panel"
        }
        Update-Layout
    })
    $historyPanelContextMenu.Items.Add($dockUndockMenuItem)
    $groupHistory.ContextMenuStrip = $historyPanelContextMenu
    
    # --- NEW: TabControl for Collections and History ---
    $collectionsTabControl = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
    }

    # --- Collections Tab ---
    $tabCollections = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Collections" }
    $treeViewCollections = New-Object System.Windows.Forms.TreeView -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
        ShowNodeToolTips = $true
        BorderStyle = [System.Windows.Forms.BorderStyle]::None
    }
    # Add an ImageList for icons
    $imageList = New-Object System.Windows.Forms.ImageList
    # Simple icons for Collection (folder), Folder (subfolder), and Request (file)
    $imageList.Images.Add([System.Drawing.SystemIcons]::Application) # Collection
    $imageList.Images.Add([System.Drawing.SystemIcons]::Information) # Folder
    $imageList.Images.Add([System.Drawing.SystemIcons]::Question)    # Request
    $treeViewCollections.ImageList = $imageList

    # --- Collections Context Menu ---
    $collectionsContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $addCollectionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("New Collection", $null, {
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new collection name:", "New Collection")
        if ($name) {
            $newCollection = [PSCustomObject]@{ Name = $name; Type = "Collection"; Items = @(); Variables = @{} } # Create new collection object
            $script:collections += $newCollection #FIX: Corrected collection creation
            Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
            Save-Collections #FIX: Corrected function call
        }
    })
    $addFolderMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("New Folder", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new folder name:", "New Folder") # Prompt for folder name
            if ($name) {
                $newFolder = [PSCustomObject]@{ Name = $name; Type = "Folder"; Items = @() }
                $selectedNode.Tag.Items += $newFolder
                Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                $selectedNode.Expand()
                Save-Collections
            }
        }
    })
    $saveRequestMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Save Current Request", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter request name:", "Save Request", "$($script:comboMethod.SelectedItem) $($script:textUrl.Text)") # Prompt for request name
            if ($name) {
                $newRequest = [PSCustomObject]@{
                    Name = $name
                    Type = "Request"
                    RequestData = [PSCustomObject]@{
                        Timestamp = Get-Date
                        Method    = $script:comboMethod.SelectedItem
                        Url       = $script:textUrl.Text
                        Headers   = $script:textHeaders.Text
                        Body      = $script:textBody.Text
                        BodyType  = $script:comboBodyType.SelectedItem
                        OutputFormat = if ($script:textOutputFormat) { [string]$script:textOutputFormat.Text } else { "" }
                        Tests     = $script:textTests.Text                        
                        PreRequestScript = $script:textPreRequest.Text
                        Authentication = (& $script:authPanel.GetAuthData)
                    }
                }
                $selectedNode.Tag.Items += $newRequest
                Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                $selectedNode.Expand()
                Save-Collections
            }
        }
    })
    $editCollectionVarsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Edit Variables...", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode -and $selectedNode.Tag.Type -eq "Collection") {
            $col = $selectedNode.Tag
            $currentVars = if ($col.PSObject.Properties.Name -contains 'Variables' -and $col.Variables) { $col.Variables } else { @{} }
            $result = Show-VariablesEditor -parentForm $form -Title "Collection Variables: $($col.Name)" -Variables $currentVars
            if ($result.Result -eq [System.Windows.Forms.DialogResult]::OK) {
                $col.Variables = if ($result.Variables) { $result.Variables } else { @{} }
                Save-Collections
                if ($script:activeCollectionNode -and $script:activeCollectionNode -eq $selectedNode) {
                    $script:activeCollectionVariables = $col.Variables
                    if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                        & $updateExtractVarList
                    }
                }
                Write-Log "Collection variables updated for '$($col.Name)'."
            }
        }
    })
    $renameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Rename", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $newName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new name:", "Rename", $selectedNode.Text) # Prompt for new name
            if ($newName) {
                $selectedNode.Tag.Name = $newName
                $selectedNode.Text = $newName
                Save-Collections
            }
        }
    })
    $deleteMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Delete", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete '$($selectedNode.Text)'?", "Confirm Delete", "YesNo", "Warning") # Confirmation dialog
            if ($confirm -eq 'Yes') {
                $parent = $selectedNode.Parent
                if ($parent) {
                    $parent.Tag.Items = @($parent.Tag.Items | Where-Object { $_ -ne $selectedNode.Tag })
                } else { # Top-level collection
                    $script:collections = @($script:collections | Where-Object { $_ -ne $selectedNode.Tag })
                }
                $selectedNode.Remove()
                Save-Collections
            }
        }
    })
    $exportFolderMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Export Folder...", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ 
                Filter = "JSON Files (*.json)|*.json"; 
                FileName = "$($selectedNode.Text)_export.json"; 
                Title = "Export Folder" 
            }
            if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                try {
                    $selectedNode.Tag | ConvertTo-Json -Depth 10 | Set-Content -Path $sfd.FileName -ErrorAction Stop
                    [System.Windows.Forms.MessageBox]::Show("Folder exported successfully.", "Export", "OK", "Information")
                } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
            }
        }
    })
    $runCollectionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run...", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            Show-CollectionRunnerWindow -Item $selectedNode.Tag -parentForm $form
        }
    })

    $collectionsContextMenu.Items.AddRange(@($addCollectionMenuItem, $addFolderMenuItem, $saveRequestMenuItem, $editCollectionVarsMenuItem, (New-Object System.Windows.Forms.ToolStripSeparator), $runCollectionMenuItem, $renameMenuItem, $deleteMenuItem, $exportFolderMenuItem))
    $treeViewCollections.ContextMenuStrip = $collectionsContextMenu

    $collectionsContextMenu.Add_Opening({
        $selectedNode = $treeViewCollections.SelectedNode
        $addFolderMenuItem.Enabled = $false
        $saveRequestMenuItem.Enabled = $false
        $editCollectionVarsMenuItem.Enabled = $false
        $renameMenuItem.Enabled = $false
        $deleteMenuItem.Enabled = $false
        $runCollectionMenuItem.Enabled = $false
        $exportFolderMenuItem.Enabled = $false

        if ($selectedNode) {
            $itemType = $selectedNode.Tag.Type
            $renameMenuItem.Enabled = $true
            $deleteMenuItem.Enabled = $true
            if ($itemType -eq "Collection" -or $itemType -eq "Folder") {
                $addFolderMenuItem.Enabled = $true
                $saveRequestMenuItem.Enabled = $true
                $runCollectionMenuItem.Enabled = $true
                $exportFolderMenuItem.Enabled = $true
            }
            if ($itemType -eq "Collection") {
                $editCollectionVarsMenuItem.Enabled = $true
            }
        }
    })

    $treeViewCollections.Add_NodeMouseClick({
        param($sender, $e)
        # Select node on right-click to make context menu work intuitively
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
            $treeViewCollections.SelectedNode = $e.Node
        }
    })

    $treeViewCollections.Add_AfterSelect({
        param($sender, $e)
        $selectedNode = $e.Node
        if ($selectedNode) {
            if ($selectedNode.Tag.Type -eq "Collection") {
                $script:activeCollectionNode = $selectedNode
                $script:activeCollectionName = $selectedNode.Tag.Name
                $script:activeCollectionVariables = if ($selectedNode.Tag.Variables) { $selectedNode.Tag.Variables } else { @{} }
                if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                    & $updateExtractVarList
                }
            } elseif ($selectedNode.Tag.Type -eq "Request") {
                # Load the request data into the form
                $selectedHistoryItem = Get-RequestObjectFromItem -Item $selectedNode.Tag
                if ($selectedHistoryItem) {
                    # This reuses the existing history loading logic
                    Load-Request-From-Object -RequestObject $selectedHistoryItem
                    Write-Log "Loaded request '$($selectedNode.Tag.Name)' from collection."
                } else {
                    [System.Windows.Forms.MessageBox]::Show("This collection entry does not contain runnable request data.", "Missing Request Data", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    Write-Log "Skipped loading collection request '$($selectedNode.Tag.Name)' because request data was missing." -Level Debug
                }

                $collectionNode = Get-CollectionNodeFromChild -node $selectedNode
                if ($collectionNode) {
                    $script:activeCollectionNode = $collectionNode
                    $script:activeCollectionName = $collectionNode.Tag.Name
                    $script:activeCollectionVariables = if ($collectionNode.Tag.Variables) { $collectionNode.Tag.Variables } else { @{} }
                    if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                        & $updateExtractVarList
                    }
                }
            } else {
                $collectionNode = Get-CollectionNodeFromChild -node $selectedNode
                if ($collectionNode) {
                    $script:activeCollectionNode = $collectionNode
                    $script:activeCollectionName = $collectionNode.Tag.Name
                    $script:activeCollectionVariables = if ($collectionNode.Tag.Variables) { $collectionNode.Tag.Variables } else { @{} }
                    if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                        & $updateExtractVarList
                    }
                }
            }
        }
    })

    # Refactored: Use a Panel with Docking strategy consistent with History tab
    $panelCollectionsBottom = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Bottom'
        Height = 60 
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5) 
    }

    $btnImportCollections = New-Button -Text "Import" -Property @{ 
        Dock = 'Left'
        Width = 180 
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 10, 0) 
    } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter = "JSON Files (*.json)|*.json"; Title = "Import Collections" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to import collections? This will append the imported items to your current list.", "Confirm Import", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
                try {
                    $imported = Get-Content -Path $ofd.FileName -Raw | ConvertFrom-Json
                        if ($imported) {
                            if ($imported -is [array]) {
                                $script:collections += $imported
                            } else {
                                $script:collections += @($imported)
                            }
                            Ensure-CollectionVariables -Items $script:collections
                            Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                            Save-Collections
                            [System.Windows.Forms.MessageBox]::Show("Collections imported successfully.", "Import", "OK", "Information")
                        }
                } catch { [System.Windows.Forms.MessageBox]::Show("Import failed: $($_.Exception.Message)", "Error", "OK", "Error") }
            }
        }
    }

    $btnExportCollections = New-Button -Text "Export" -Property @{ 
        Dock = 'Left'
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
        Width = 180
    } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter = "JSON Files (*.json)|*.json"; FileName = "api_tester_collections_export.json"; Title = "Export Collections" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:collections | ConvertTo-Json -Depth 10 | Set-Content -Path $sfd.FileName -ErrorAction Stop
                [System.Windows.Forms.MessageBox]::Show("Collections exported successfully.", "Export", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }

    # Add controls in docking order (Left, then Left)
    $panelCollectionsBottom.Controls.AddRange(@($btnImportCollections, $btnExportCollections))

    $tabCollections.Controls.AddRange(@($treeViewCollections, $panelCollectionsBottom))

    # --- History Tab ---
    $tabHistory = New-Object System.Windows.Forms.TabPage -Property @{ Text = "History" }
    
    # Refactored: Use a Panel with Docking strategy consistent with main layout
    $searchHistoryPanel = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Top'
        Height = 45
        Padding = [System.Windows.Forms.Padding]::new(5, 10, 5, 5)
    }

    $comboHistoryEnvFilter = New-Object System.Windows.Forms.ComboBox -Property @{ 
        Dock = 'Right'
        Width = 180 
        DropDownWidth = 240 
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        Margin = [System.Windows.Forms.Padding]::new(10, 0, 0, 0) 
    }
    $toolTip.SetToolTip($comboHistoryEnvFilter, "Filter history by environment")
    
    $textSearchHistory = New-TextBox -Property @{ 
        Dock = 'Fill'
        Text = "Search by Method/URL..." 
        ForeColor = [System.Drawing.Color]::Gray 
    }
    $toolTip.SetToolTip($textSearchHistory, "Search by method or URL")

    # Add placeholder text functionality
    $textSearchHistory.Add_Enter({ 
        if ($textSearchHistory.Text -eq "Search by Method/URL...") { 
            $textSearchHistory.Text = ""; 
            $textSearchHistory.ForeColor = [System.Drawing.Color]::Black 
        } 
    })
    $textSearchHistory.Add_Leave({ 
        if ([string]::IsNullOrWhiteSpace($textSearchHistory.Text)) { 
            $textSearchHistory.Text = "Search by Method/URL..."; 
            $textSearchHistory.ForeColor = [System.Drawing.Color]::Gray 
        } 
    })

    # Add the event handler to filter the list as the user types
    $textSearchHistory.Add_TextChanged({
        param($sender, $e)
        # Avoid filtering when the placeholder text is present
        if ($sender.Text -ne "Search by Method/URL...") {
            Populate-HistoryList -TextFilter $sender.Text -EnvironmentFilter $comboHistoryEnvFilter.SelectedItem
        }
    })

    $comboHistoryEnvFilter.Add_SelectedIndexChanged({
        if ($textSearchHistory.Text -eq "Search by Method/URL...") { $textFilter = "" } else { $textFilter = $textSearchHistory.Text }
        Populate-HistoryList -TextFilter $textFilter -EnvironmentFilter $comboHistoryEnvFilter.SelectedItem
    })

    # Add controls to panel and apply docking precedence
    # Note: Search field (Fill) first, then dropdown (Right) to ensure proper layout
    $searchHistoryPanel.Controls.AddRange(@($textSearchHistory, $comboHistoryEnvFilter))

    $listHistory = New-Object System.Windows.Forms.ListBox -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
        BorderStyle = [System.Windows.Forms.BorderStyle]::None
    }
    
    # Refactored: Use a Panel with Docking strategy consistent with Collections tab
    $panelHistoryBottom = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Bottom'
        Height = 60 
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5) 
    }
    
    $btnClearHistory = New-Button -Text "Clear History" -Style 'Danger' -Property @{ 
        Dock = 'Left'
        Width = 180
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 10, 0) 
    } -OnClick {
        $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to clear all history? This cannot be undone.", "Confirm Clear", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $script:history = @()
            $listHistory.Items.Clear()
            Save-History
        }
    }
    
    $btnExportHistory = New-Button -Text "Export History" -Property @{ 
        Dock = 'Left'
        Width = 180
    } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter = "JSON Files (*.json)|*.json"; FileName = "api_tester_history_export.json"; Title = "Export History" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:history | ConvertTo-Json -Depth 10 | Set-Content -Path $sfd.FileName -ErrorAction Stop
                [System.Windows.Forms.MessageBox]::Show("History exported successfully.", "Export", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }
    $panelHistoryBottom.Controls.AddRange(@($btnClearHistory, $btnExportHistory))
    $tabHistory.Controls.AddRange(@($listHistory, $searchHistoryPanel, $panelHistoryBottom))

    $historyContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $duplicateHistoryItem = New-Object System.Windows.Forms.ToolStripMenuItem("Duplicate", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $historyObject = $selectedItem.Value
            $script:activeCollectionName = $null
            $script:activeCollectionNode = $null
            $script:activeCollectionVariables = @{}
            Load-Request-From-Object -RequestObject $historyObject
            Write-Log "Duplicated request from history: $($historyObject.Url)"
        }
    })
    $deleteHistoryItem = New-Object System.Windows.Forms.ToolStripMenuItem("Delete", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $historyObjectToRemove = $selectedItem.Value
            $listHistory.Items.Remove($selectedItem)
            $script:history = $script:history | Where-Object { $_ -ne $historyObjectToRemove }
            Save-History
            Write-Log "Deleted history item: $($historyObjectToRemove.Url)"
        }
    })    
    $copyAsCurlMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Copy as cURL", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $selectedHistoryItem = $selectedItem.Value
            $curlCommand = Generate-CodeSnippet -RequestItem $selectedHistoryItem -Language "cURL"
            [System.Windows.Forms.Clipboard]::SetText($curlCommand) # Copy to clipboard
            Write-Log "Copied history item as cURL command to clipboard."
        }
    })
    $copyAsPSMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Copy as PowerShell", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $selectedHistoryItem = $selectedItem.Value
            $psCommand = Generate-CodeSnippet -RequestItem $selectedHistoryItem -Language "PowerShell"
            [System.Windows.Forms.Clipboard]::SetText($psCommand)
            Write-Log "Copied history item as PowerShell command to clipboard."
        }
    })

    $historyContextMenu.Items.AddRange(@($duplicateHistoryItem, $copyAsCurlMenuItem, $copyAsPSMenuItem, $deleteHistoryItem))
    $listHistory.ContextMenuStrip = $historyContextMenu

    $listHistory.Add_MouseDown({
        param($sender, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
            $index = $listHistory.IndexFromPoint($e.Location)
            if ($index -ne [System.Windows.Forms.ListBox]::NoMatches) {
                $listHistory.SelectedIndex = $index
            }
        }
    })
    $historyContextMenu.Add_Opening({
        $_.Cancel = ($listHistory.SelectedIndex -eq -1)
    })

    # Central function to load a request object into the UI fields
    function Load-Request-From-Object {
        param(
            # Accept the named parameter used elsewhere (-RequestObject) and positional calls.
            [AllowNull()]
            [Parameter(Position=0)]
            [object]$RequestObject
        )

        # If caller used the old variable name internally, normalize to $selectedHistoryItem for the rest of the function.
        $selectedHistoryItem = $RequestObject
        if (-not $selectedHistoryItem) {
            Write-Log "Load-Request-From-Object was called without request data." -Level Debug
            return
        }

        $script:textUrl.Text = $selectedHistoryItem.Url
        $script:comboMethod.SelectedItem = $selectedHistoryItem.Method
        
        # Set body text BEFORE setting body type and mode, so the correct content is parsed.
        $script:textBody.Text = $selectedHistoryItem.Body
        $script:comboBodyType.SelectedItem = $selectedHistoryItem.BodyType
        Set-BodyEditorMode

        $script:textHeaders.Text = $selectedHistoryItem.Headers

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'OutputFormat') {
            $script:textOutputFormat.Text = [string]$selectedHistoryItem.OutputFormat
        } else {
            $script:textOutputFormat.Text = ""
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'Tests') {
            $script:textTests.Text = $selectedHistoryItem.Tests
        } else {
            $script:textTests.Text = ""
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'PreRequestScript') {
            $script:textPreRequest.Text = $selectedHistoryItem.PreRequestScript
        } else {
            $script:textPreRequest.Text = ""
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'Environment') {
            if ($script:comboEnvironment.Items.Contains($selectedHistoryItem.Environment)) {
                $script:comboEnvironment.SelectedItem = $selectedHistoryItem.Environment
            }
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'Authentication') {
            # Temporarily remove the event handler to prevent it from firing and clearing the panel
            $authTypeChangedHandler = $script:authPanel.ComboAuthType.SelectedIndexChanged # Store event handler
            $script:authPanel.ComboAuthType.remove_SelectedIndexChanged($authTypeChangedHandler)

            $auth = $selectedHistoryItem.Authentication
            $script:authPanel.ComboAuthType.SelectedItem = $auth.Type
            & $script:authPanel.SwitchPanel # Manually trigger the panel switch
            switch ($auth.Type) {
                "API Key"      { $script:authPanel.TextApiKeyName.Text = $auth.Key; $script:authPanel.TextApiKeyValue.Text = $auth.Value; $script:authPanel.ComboApiKeyAddTo.SelectedItem = $auth.AddTo }
                "Bearer Token" { $script:authPanel.TextBearerToken.Text = $auth.Token }
                "Basic Auth"   { $script:authPanel.TextBasicUser.Text = $auth.Username; $script:authPanel.TextBasicPass.Text = $auth.Password }
                "Auth2"        {
                    $script:authPanel.TextAuth2ClientId.Text = $auth.ClientId
                    $script:authPanel.TextAuth2ClientSecret.Text = $auth.ClientSecret
                    $script:authPanel.TextAuth2TokenEndpoint.Text = $auth.TokenEndpoint
                    $script:authPanel.TextAuth2Scope.Text = $auth.Scope
                    $script:authPanel.TextAuth2AccessToken.Text = $auth.AccessToken
                    $script:authPanel.TextAuth2RefreshToken.Text = $auth.RefreshToken
                    $script:authPanel.TextAuth2ExpiresIn.Text = $auth.ExpiresIn
                    $script:authPanel.TextAuth2AccessToken.Tag = $auth.TokenExpiryTimestamp
                }
                "Client Certificate" {
                    $script:authPanel.ComboCertSource.SelectedItem = $auth.Source
                    $script:authPanel.TextCertPath.Text = $auth.Path
                    $script:authPanel.TextCertPass.Text = $auth.Password
                    $script:authPanel.TextCertThumb.Text = $auth.Thumbprint
                }
            }

            # Re-add the event handler
            $script:authPanel.ComboAuthType.add_SelectedIndexChanged($authTypeChangedHandler) # Re-add event handler
        } else {
            $script:authPanel.ComboAuthType.SelectedItem = "No Auth"
        }

        $checkIncludeFilename.Checked = $script:settings.IncludeFilename
        $checkIncludeContentType.Checked = $script:settings.IncludeContentType
        # After loading the body and setting the checkboxes, re-apply the attributes
        # to ensure the file lines are correctly formatted for the current settings.
        Apply-Attributes-To-AllFileLines

        # Update Code Snippet
        $currentUiRequest = [PSCustomObject]@{
            Method = $script:comboMethod.SelectedItem
            Url = $script:textUrl.Text
            Headers = $script:textHeaders.Text
            Body = $script:textBody.Text
            BodyType = $script:comboBodyType.SelectedItem
        }
        $script:lastRequestState = $currentUiRequest
        $richTextCode.Text = Generate-CodeSnippet -RequestItem $currentUiRequest -Language $script:comboCodeLanguage.SelectedItem
    }

    $script:comboBodyType.Add_SelectedIndexChanged({
        Set-BodyEditorMode
        if (-not $script:isSwitchingRequestTab) { Save-ActiveRequestTabState }
    })

    if ($script:settings.EnableHistory) {
        Load-History
    }    
    Populate-HistoryList -TextFilter "" -EnvironmentFilter "All Environments" 
    Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections

    $listHistory.Add_SelectedIndexChanged({
        # This event is intentionally left empty to prevent a race condition with the DoubleClick event.
    })

    $checkIncludeFilename.Add_CheckedChanged({
        $script:settings.IncludeFilename = $checkIncludeFilename.Checked
        Save-Settings
        Apply-Attributes-To-AllFileLines
    })
    $checkIncludeContentType.Add_CheckedChanged({
        $script:settings.IncludeContentType = $checkIncludeContentType.Checked
        Save-Settings
        Apply-Attributes-To-AllFileLines
    })
    $listHistory.Add_DoubleClick({
        if ($listHistory.SelectedIndex -ne -1) {
            $selectedListItem = $listHistory.SelectedItem
            $selectedHistoryItem = Get-RequestObjectFromItem -Item $selectedListItem.Value
            if (-not $selectedHistoryItem) {
                [System.Windows.Forms.MessageBox]::Show("The selected history entry is empty or invalid.", "Missing Request Data", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                Write-Log "Skipped loading history item because the selected entry did not contain request data." -Level Debug
                return
            }
            $script:activeCollectionName = $null
            $script:activeCollectionNode = $null
            $script:activeCollectionVariables = @{}
            Load-Request-From-Object -RequestObject $selectedHistoryItem
            Write-Log "Loaded request from history via double-click (URL: $($selectedHistoryItem.Url))"

            # Force the message queue to process all pending UI updates from Load-Request-From-Object
            # before checking the body content for auto-run.
            [System.Windows.Forms.Application]::DoEvents()
            
            # Now that the data is loaded and the UI is updated, check if we should auto-run.
            if ($script:settings.AutoRunHistory) {
                $method = $script:comboMethod.Text
                # Check if the method requires a body and if the body is actually empty.
                # This check now happens *after* DoEvents() ensures the textbox is populated.
                if (($method -in @('POST', 'PUT', 'PATCH')) -and ([string]::IsNullOrWhiteSpace($script:textBody.Text))) {
                    [System.Windows.Forms.MessageBox]::Show("Cannot auto-run a $method request with an empty body. Please provide a body or run the request manually.", "Missing Request Data", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                } else {
                    $btnSubmit.PerformClick()
                }
            }
        }
    })

    $groupRequest.Controls.Add($panelRequestTabsTop)
    $groupRequest.Controls.Add($panelRequestTop)
    $groupRequest.Controls.Add($requestTabControl)
    # Ensure correct Z-order: TabControl (Fill) at index 0 (Front), request panels above it.
    $groupRequest.Controls.SetChildIndex($requestTabControl, 0)
    $groupRequest.Controls.SetChildIndex($panelRequestTop, 1)
    $groupRequest.Controls.SetChildIndex($panelRequestTabsTop, 2)
    $groupHistory.Controls.Add($collectionsTabControl)

    # Add controls to the SplitContainer panels
    $mainContentPanel.Controls.AddRange(@(
        $groupEnvironment,
        $groupRequest,        $groupOutput    ))
    $splitContainer.Panel2.Controls.Add($groupHistory)
    $collectionsTabControl.TabPages.AddRange(@($tabCollections, $tabHistory))

    $form.Controls.AddRange(@(
        $splitContainer,
        $menuStrip,
        $statusStrip
    ))

    Populate-EnvironmentDropdown
    Populate-HistoryEnvironmentFilter
    Refresh-RequestTabsStrip
    Apply-RequestStateToUi -RequestState (Get-ActiveRequestTabState)

    if ($script:settings.AutoSaveToFile) {
        $script:textOutputFile.Text = $script:settings.AutoSavePath
    }
    
    Update-Layout

    $form.Add_Shown({
        # A second call to Update-Layout after the form is shown ensures all control
        # dimensions are correctly calculated for the final layout.
        Update-Layout

        # Make launch more reliable when PowerShell/WinForms leaves the window behind
        # other apps or in a minimized/invisible state.
        try { $form.ShowInTaskbar = $true } catch {}
        try { $form.Opacity = 1 } catch {}
        try {
            if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
                $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            }
        } catch {}
        try { $form.BringToFront() } catch {}
        try {
            $form.TopMost = $true
            $form.TopMost = $false
        } catch {}
        try { $form.Activate() } catch {}
        Write-Log "Main form shown. WindowState=$($form.WindowState); Visible=$($form.Visible)"
    })

    # Add global keyboard shortcuts
    $form.Add_KeyDown({
        param($sender, $e)
        # Ctrl+Enter to Send Request
        if ($e.Control -and $e.KeyCode -eq 'Enter') {
            if ($btnSubmit.Enabled) {
                $btnSubmit.PerformClick()
                $e.SuppressKeyPress = $true
            }
        }
    })

    # Add a FormClosing handler to the main form for proper cleanup of undocked windows
    $form.Add_FormClosing({
        param($sender, $e)
        Write-Log "Main form closing event triggered."
        # Set flag to indicate main form is closing
        $script:isMainFormClosing = $true
        if ($notifyIcon) {
            try { $notifyIcon.Visible = $false } catch {}
        }
        if ($script:requestTimer) {
            try { $script:requestTimer.Stop() } catch {}
        }
        if ($script:collectionRunDelayTimer) {
            try { $script:collectionRunDelayTimer.Stop() } catch {}
        }
        if ($monitorTimer) {
            try { $monitorTimer.Stop() } catch {}
            try { $monitorTimer.Dispose() } catch {}
            $monitorTimer = $null
        }
        # Hide undocked forms so they do not briefly reactivate the owner while the main form
        # is closing. They will be disposed after shutdown completes.
        if ($script:historyForm -and -not $script:historyForm.IsDisposed) {
            Write-Log "Hiding undocked history form during shutdown."
            try { $script:historyForm.Hide() } catch {}
        }
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) {
            Write-Log "Hiding undocked response form during shutdown."
            try { $script:responseForm.Hide() } catch {}
        }
        foreach ($ownedForm in @($form.OwnedForms)) {
            if ($ownedForm -and -not $ownedForm.IsDisposed) {
                try { $ownedForm.Hide() } catch {}
            }
        }
        # Cleanup RunspacePool
        if ($script:monitorPool) {
            $script:monitorPool.Close()
            $script:monitorPool.Dispose()
            $script:monitorPool = $null
        }
        # Perform cleanup for background jobs and timers
        # (The cleanup after Application::Run is still there, but this is more robust)
        # Allow the main form to close
        $e.Cancel = $false
        Write-Log "Main form allowed to close."
    })
    $form.Add_FormClosed({
        param($sender, $e)
        if ($notifyIcon) {
            try { $notifyIcon.Visible = $false } catch {}
            try { $notifyIcon.Dispose() } catch {}
            $notifyIcon = $null
        }
        if ($script:historyForm -and -not $script:historyForm.IsDisposed) {
            try { $script:historyForm.Dispose() } catch {}
            $script:historyForm = $null
        }
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) {
            try { $script:responseForm.Dispose() } catch {}
            $script:responseForm = $null
        }
    })
    $form.ShowDialog() | Out-Null
    # Perform cleanup after the main form is closed.
    if ($script:currentPowerShell) { $script:currentPowerShell.Dispose() }
    foreach ($mId in $script:monitorJobs.Keys) {
        $entry = $script:monitorJobs[$mId]
        if ($entry.PS) { $entry.PS.Dispose() }
    }
    if ($script:monitorPool) { $script:monitorPool.Close(); $script:monitorPool.Dispose() }
    if ($script:requestTimer) { $script:requestTimer.Stop(); $script:requestTimer.Dispose() }
    if ($script:historyForm -and -not $script:historyForm.IsDisposed) { $script:historyForm.Dispose() }
    if ($script:responseForm -and -not $script:responseForm.IsDisposed) { $script:responseForm.Dispose() } # Ensure response form is disposed
    if ($notifyIcon) { $notifyIcon.Dispose() }
    $form.Dispose() # Release main form resources
}

#endregion


