/*
John Breen
Andrew Botelho 
Iveri Prangishvili
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <regex.h>
#include <string>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>

using namespace std;

#define NETSTAT_RTXCMD "sudo ethtool -S wlan0 | grep tx_retries:"
#define NETSTAT_TXCMD "sudo ethtool -S wlan0 | grep tx_packets:"

/*Grabs transmission data from system*/
int grab_wstat_txinfo(int* seg_send)
{
  	char buf[10000];  
  	FILE *p = popen(NETSTAT_TXCMD, "r");
  	std::string tx;
  	for (size_t count; (count = fread(buf, 1, sizeof(buf), p));)
  	    tx += string(buf, buf + count);
    pclose(p);  
	
	char* str = (char*)malloc(100);
	sscanf(tx.c_str(), "%s %d", str, seg_send);
    
    return 0;
}

/*Grabs retransmission data from system*/
int grab_wstat_rtxinfo(int* seg_retrans)
{
  	char buf[10000];  
  	FILE *p = popen(NETSTAT_RTXCMD, "r");
  	std::string rtx;
  	for (size_t count; (count = fread(buf, 1, sizeof(buf), p));)
  	    rtx += string(buf, buf + count);
    pclose(p);    

	char* str = (char*)malloc(100);
	sscanf(rtx.c_str(), "%s %d", str, seg_retrans);
    
    return 0;
}




#define CHANGE_TXPOWER "sudo iwconfig wlan0 txpower %d" 

int main(int argc, char *argv[]) {
		int max_power = 16;
		int beacon = 0;
		int daemon = 0;
		int no_activity = 0;
		int weighted = 0;
        char* wlan_adpt;
        
        for (int x = 1; x < argc; x++)
        {
			/* '-' character is a binary that signals to turn a feature on or off*/
			if ((argv[x])[0] == '-')
			{
				if ((argv[x])[1] == 'B')
				{
					//turns beacon mode on
					beacon = 1;
					cout << "Beacon Mode On! Warning: Use Only if Access Point!" << endl;
				}
				if ((argv[x])[1] == 'D')
				{
					//turns daemon mode on
					daemon = 1;
					cout << "Running In Daemon Mode!" << endl;
				}
				if ((argv[x])[1] == 'W')
				{
					//turns weighted shifting mode on
					weighted = 1;
					cout << "Weighted Shifts Enabled!" << endl;
				}
				if ((argv[x])[1] == 'P')
				{
					//specify power level setting
					if (x+1 >= argc)
					{
						cout << "P requires an additional parameter" << endl;
					}
					else
					{
						cout << "Max Power Changed from 16 to " << argv[x+1] << endl;
						max_power = atoi(argv[x+1]);
						x++;
					}
					
				}
				else
				{
					cout << "Invalid Parameter!" << endl;
				}
			}
			/* Currently only other parameter is wireless adapter */
			else
			{
				wlan_adpt = strdup(argv[x+1]);
			}
		}
        
		if  (daemon)
		{
			cout<< "Starting Daemon" << endl;
			/* Our process ID and Session ID */
			pid_t pid, sid;
			
			/* Fork off the parent process */
			pid = fork();
			if (pid < 0) {
					exit(EXIT_FAILURE);
			}
			/* If we got a good PID, then
			   we can exit the parent process. */
			if (pid > 0) {
					exit(EXIT_SUCCESS);
			}

			/* Change the file mode mask */
			umask(0);
					
			/* Open any logs here */        
					
			/* Create a new SID for the child process */
			sid = setsid();
			if (sid < 0) {
					/* Log the failure */
					exit(EXIT_FAILURE);
			}
			

			
			/* Change the current working directory */
			if ((chdir("/")) < 0) {
					/* Log the failure */
					exit(EXIT_FAILURE);
			}
			
			/* Close out the standard file descriptors */
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
		}
        
        /* Initialization of Daemon */
        int ctx_power = 16;
        int weighted_shift = max_power;
        int changed_power = 0;
        int bcount = 0;
        int rtx_diff, tx_diff;
        int* iseg_tx, *iseg_rtx, *fseg_tx, *fseg_rtx;
        iseg_tx = (int *)malloc(sizeof(int));
        iseg_rtx = (int *)malloc(sizeof(int));
        fseg_tx = (int *)malloc(sizeof(int));
        fseg_rtx = (int *)malloc(sizeof(int));
        
        
        
        cout << "Starting Loop" << endl;
        
        rtx_diff = 1;
        tx_diff = 1;
        /* The Big Loop */
        while (1) {
      		if (rtx_diff != 0 || tx_diff != 0)
      		{
				no_activity = 0;
				/* This part still experimental, but theoretically if super high retransmit, then increase power faster*/
				if (weighted && tx_diff != 0 && rtx_diff >= tx_diff * 5)
				{
					/* Increases increments of weighted shift by factor of 2 */
					weighted_shift *= 4;
					weighted_shift > max_power ? weighted_shift = max_power : weighted_shift;
				}
				
      			/* Packet retransmission > 10% is considered high */
      			if (rtx_diff * 10 >= tx_diff)
      			{
      				if (ctx_power != max_power){
						/* Weighted Shifts on Increasing Transmission Power*/
						if (weighted)
						{
							weighted_shift /= 2;
							weighted_shift < 1 ? weighted_shift = 1 : weighted_shift;
							ctx_power + weighted_shift > max_power ? ctx_power = max_power : ctx_power += weighted_shift;
						}
						else
						{
							ctx_power++;
						}
      					changed_power = 1;
      				}
      			}
      			else 
      			{
      				if (ctx_power != 0){
						/* Weighted Shifts on Decreasing Transmission Power */
						if (weighted)
						{
							weighted_shift /= 2;
							weighted_shift < 1 ? weighted_shift = 1 : weighted_shift;
							ctx_power - weighted_shift < 0 ? ctx_power = 0 : ctx_power -= weighted_shift;
						}
						else
						{
							ctx_power--;
						}
      					changed_power = 1;
      				}
      			}
      			char tx_cmd[100];
      			
      			sprintf(tx_cmd, CHANGE_TXPOWER, ctx_power);
      			
      			if (changed_power){
      				cout << tx_cmd << endl;
      			
      				system(tx_cmd);
      			}
      			changed_power = 0;
      			
      			grab_wstat_txinfo(iseg_tx);
           		grab_wstat_rtxinfo(iseg_rtx);
      		}
      		else{
				no_activity++;
			}
			
			if (no_activity == 5){
				char noact_cmd[100];
				
				sprintf(noact_cmd, CHANGE_TXPOWER, 0);
				system(noact_cmd);
			}
           	
            sleep(1); /* wait 1 second */
            
            grab_wstat_txinfo(fseg_tx);
            grab_wstat_rtxinfo(fseg_rtx);
            
            /* Calculates retransmission and transmission */
            rtx_diff =  (*fseg_rtx) - (*iseg_rtx);
            tx_diff = (*fseg_tx) - (*iseg_tx);
            
            /* Beacons the signal to other devices so they can see it */
            if (beacon && bcount > 5)
            {
				if (ctx_power != max_power)
				{
					char tx_cmd[100];
					sprintf(tx_cmd, CHANGE_TXPOWER, max_power);
					system(tx_cmd);
				}
				bcount = 0;
				sleep(2);
			}
			else{
				bcount++;
			}
        }
   exit(EXIT_SUCCESS);
}

