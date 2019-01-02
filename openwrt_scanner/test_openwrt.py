import  subprocess
import atexit

logger = logging.getLogger('scan_openwrt.py')

def run_continouesly(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    while True:
        line = process.stdout.readline().rstrip()
        if not line:
            break
        yield line

def run(commnad):
    p = subprocess.Popen(commnad, shell=True, stdin=subprocess.PIPE,
	                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
	
    output, err = p.communicate()
    output = output
    if err != None:
        print("Err:" ,err)
    return output


def get_first_wifi_card():
	cmd = "iw dev  | grep Interface | awk '{print $2 }'"
	p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
	                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
	output = p.stdout.read()
	return output

def tcpdump_is_running():
	ps_output = subprocess.Popen(
		"ps", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ps_stdout = ps_output.stdout.read()
	isRunning = 'tcpdump' in ps_stdout and '[tcpdump]' not in ps_stdout
	#print("tcpdump is running: " + str(isRunning))
	return isRunning

def exit_handler():
    print("Exiting...stopping scan..")
    tcpdumpPID = run("ps | grep tcpdump | awk '{print $1 }'") ######
    run("kill "+tcpdumpPID)
    print(run("  airmon-zc stop "+get_first_wifi_card()))

if __name__ == "__main__":
    atexit.register(exit_handler)


    print(run("airmon-zc start "+get_first_wifi_card()))
    tcpdump_is_running()
    for path in run_continouesly("  tcpdump -nni "+get_first_wifi_card()+" -v"):
        if (tcpdump_is_running()):
            print(path)
        else:
            break
    tcpdump_is_running()
    print(run("airmon-zc stop "+get_first_wifi_card()))