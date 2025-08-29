import os
import signal
import time
import subprocess

def test_hist():

    get_ngx = subprocess.Popen(['apt install nginx -y'],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                text=True,
                                                shell=True)
    _, _ = get_ngx.communicate()
    #ikr?


    nginx = subprocess.Popen(['nginx -c $(pwd)/test/minimal-return.conf'], shell=True)
    nginx_pid = nginx.pid
    time.sleep(1)

    #looks odd but the event loops are shorter than 1 microsecond otherwise
    curl = subprocess.Popen(['while true; do curl -sS http://127.0.0.1:8080/ -o/dev/null; done'], shell=True)
    curl_pid = curl.pid
    time.sleep(1)

    ngx_event_loop_histogram = subprocess.Popen(['objs/ngx_event_loop_histogram'],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                text=True)
    stdout, stderr = ngx_event_loop_histogram.communicate()
    os.kill(nginx_pid, signal.SIGTERM)
    os.kill(curl_pid, signal.SIGTERM)
    nginx.wait()
    curl.wait()

    assert stdout.count('nginx_event_loop_duration_usec_bucket') == 25

    nonzero_usec = 0
    for line in stdout.splitlines():
        if not line.endswith(' 0'):
            nonzero_usec += 1

    assert nonzero_usec != 0


#python3 -m pytest -v  test/test.py
