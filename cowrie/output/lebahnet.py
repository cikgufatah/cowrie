"""
LebahNET Output Connector
Author: Ahmad Ramadhan Amizudin
"""
from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.python import log

import cowrie.core.output
from datetime import datetime
import requests
import json

class Output(cowrie.core.output.Output):

    debug = False
    def __init__(self, cfg):
        self.cfg = cfg
        cowrie.core.output.Output.__init__(self, cfg)

    def start(self):
        pass

    def stop(self):
        pass

    def submitArtifact(self, sensor_id, connection_id, args):
        artifact_url = self.cfg.get('output_lebahnet', 'artifact_url')
        url = artifact_url.format(id=sensor_id, connection_id=connection_id)
        r = requests.post(url, data=args, verify=False, timeout=15)
        return r

    def write(self, entry):
        self.connection_url = self.cfg.get('output_lebahnet', 'connection_url').format(id=self.sensor)
        self.artifact_url = self.cfg.get('output_lebahnet', 'artifact_url')

        if entry["eventid"] == 'cowrie.session.connect':
            protocol =  "telnetd" if "telnet" in entry['system'].lower() else "sshd"
            r = requests.post(self.connection_url,
                data = {
                    "hash": entry['session'],
                    "src_ip": entry['src_ip'],
                    "src_port": entry['src_port'],
                    "dst_ip": entry['dst_ip'],
                    "dst_port": entry['dst_port'],
                    "transport": "tcp",
                    "protocol": protocol,
                    "timestamp": str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                },
                verify=False,
                timeout=15
            )

        elif entry["eventid"] == 'cowrie.login.success':
            source =  "telnet" if "telnet" in entry['system'].lower() else "ssh"
            self.submitArtifact(self.sensor, entry['session'], {
                    "type": "bruteforce",
                    "metadata": json.dumps({
                        "username": entry['username'],
                        "password": entry['password'],
                        "success": "yes",
                        "source":  source,
                        "timestamp": str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    })
            })

        elif entry["eventid"] == 'cowrie.login.failed':
            source =  "telnet" if "telnet" in entry['system'].lower() else "ssh"
            self.submitArtifact(self.sensor, entry['session'], {
                    "type": "bruteforce",
                    "metadata": json.dumps({
                        "username": entry['username'],
                        "password": entry['password'],
                        "success": "no",
                        "source":  source,
                        "timestamp": str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    })
            })

        elif entry["eventid"] == 'cowrie.command.success':
            if entry['input'] != "":
                self.submitArtifact(self.sensor, entry['session'], {
                        "type": "shellcmd",
                        "metadata": json.dumps({
                            "cmd": entry['input'],
                            "success": "yes",
                            "timestamp": str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        })
                })

        elif entry["eventid"] == 'cowrie.command.failed':
            if entry['input'] != "":
                self.submitArtifact(self.sensor, entry['session'], {
                        "type": "shellcmd",
                        "metadata": json.dumps({
                            "cmd": entry['input'],
                            "success": "no",
                            "timestamp": str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        })
                })

        elif entry["eventid"] == 'cowrie.session.file_download':
            url = self.artifact_url.format(id=self.sensor, connection_id=entry['session'])
            files = {
                'upfile': open( entry['outfile'], 'rb' )
            }
            values = {
                'type': 'fileupload',
                'md5': entry['shasum'],
                'metadata': json.dumps({
                    'url': entry['url'],
                    'md5': entry['shasum'],
                    'timestamp': str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                })
            }
            requests.post(url, files=files, data=values, verify=False);

        elif entry["eventid"] == 'cowrie.client.version':
            self.submitArtifact(self.sensor, entry['session'],{
                "type": "sshbanner",
                "metadata": json.dumps({
                    "banner": entry['version'],
                    "timestamp": str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                })
            })

        elif entry["eventid"] == 'cowrie.client.size':
            pass

        elif entry["eventid"] == 'cowrie.session.closed':
            pass

        elif entry["eventid"] == 'cowrie.log.closed':
            pass

        elif entry["eventid"] == 'cowrie.client.fingerprint':
            pass
