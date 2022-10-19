package postee.trivyoperator.email

title:=sprintf("Trivy Operator %s Report for - %s", [input.kind, input.metadata.name])

result:= res {
	res:= [
		{ "type":"section",
		 "text": {"type":"mrkdwn","text": sprintf("*CRITICAL:* %d", [input.report.summary.criticalCount])}},
		{ "type":"section",
		 "text": {"type":"mrkdwn","text": sprintf("*HIGH:* %d", [input.report.summary.highCount])}},
	]
   }

tpl :=`
<p> Severity: %s </p>
<p> vulnerabilityID: %s </p>
<p> primaryLink: %s </p>
`

vulnIDs := vulnIdResult {
    var := [ scan | 
   
            item1:=input.vulnerabilities[i].vulnerabilityID
            scan:=item1
    ] 
	
    vulnIdResult:= concat("n", (var))
}

svrt := svrtResult {
    var := [ scan | 
   
            item1:=input.vulnerabilities[i].severity
            scan:=item1
    ] 
	
    svrtResult:= concat("\n", (var))
}

link := linkResult {
    var := [ scan | 
   
            item1:=input.vulnerabilities[i].primaryLink
            scan:=item1
    ] 
	
    linkResult:= concat("\n", (var))
}

result:= res {
 res:= sprintf(tpl, [
 svrt,
 vulnIDs,
 link
 ])
 }