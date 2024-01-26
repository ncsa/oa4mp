package edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc;

import edu.uiuc.ncsa.oa4mp.delegation.server.storage.BaseClientStore;
import edu.uiuc.ncsa.security.core.cache.MyThread;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/10/23 at  11:41 AM
 */
public class UUCThread extends MyThread {
    public UUCThread(String name,
                     MyLoggingFacade logger,
                     BaseClientStore clientStore,
                     UUCConfiguration uucConfiguration) {
        super(name, logger);
        this.baseClientStore = clientStore;
        this.uucConfiguration = uucConfiguration;
    }
   UUCConfiguration uucConfiguration;
    BaseClientStore baseClientStore;

    public boolean isStopThread() {
        return stopThread;
    }

    public void setStopThread(boolean stopThread) {
        this.stopThread = stopThread;
    }

    boolean stopThread = false;



    @Override
    public void run() {
        info("starting cleanup thread for " + getName());
        while (!isStopThread()) {
            try {
                Date nextRun = new Date();
                long nextCleanup = getNextSleepInterval();
                if (nextCleanup <= 0) {
                    // this disables the thread.
                    warn("Thread disabled for " + getName() + ". Exiting...");
                    setStopThread(true); //just in case
                    return;
                }
                nextRun.setTime(nextRun.getTime() + nextCleanup);
             //   info("next iteration for " + getName() + " scheduled for " + nextRun);
                sleep(nextCleanup);

            BaseClientStore.UUCResponse uucResponse = baseClientStore.unusedClientCleanup(uucConfiguration);
            if(uucConfiguration.testMode){
                info(getName() + " in test mode. Client stats: " + uucResponse);
                info(getName() + " in test mode. Clients to remove: " + uucResponse.found);
            }
            info(getName() + ": tried=" + uucResponse.attempted + ", success =" + (uucResponse.success + uucResponse.no_info));
            } catch (InterruptedException e) {
                setStopThread(true); // just in case.
                warn("Cleanup for " + getName() + " interrupted, stopping thread...");
            }
        }
    }
}
