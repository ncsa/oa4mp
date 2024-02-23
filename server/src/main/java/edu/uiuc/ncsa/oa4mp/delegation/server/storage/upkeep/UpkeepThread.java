package edu.uiuc.ncsa.oa4mp.delegation.server.storage.upkeep;

import edu.uiuc.ncsa.security.core.cache.MyThread;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.MonitoredStoreInterface;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConfiguration;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepResponse;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/10/23 at  11:41 AM
 */
public class UpkeepThread extends MyThread {
    public UpkeepThread(String name,
                        MyLoggingFacade logger,
                        MonitoredStoreInterface store) {
        super(name, logger);
        this.monitoredStore = store;
        init();
    }

    protected void init() {
        if (getCfg().hasAlarms()) {
            setAlarms(getCfg().getAlarms());
        } else {
            setCleanupInterval(getCfg().getInterval()); // there  is always a default interval
        }
        setTestMode(false); // Used in cleanup age() method, not used here.
        counter = getCfg().getRunCount();
    }
    int counter = -1; // number of times to run before exiting.
    MonitoredStoreInterface monitoredStore;

    public boolean isStopThread() {
        return stopThread && (counter == 0);
    }

    public void setStopThread(boolean stopThread) {
        this.stopThread = stopThread;
    }

    boolean stopThread = false;

    protected UpkeepConfiguration getCfg() {
        return monitoredStore.getUpkeepConfiguration();
    }

    @Override
    public void run() {
        info("starting " + getName());
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
                if(0 < counter){
                      counter--;
                  }
                sleep(nextCleanup);

                try {
                    UpkeepResponse upkeepResponse = monitoredStore.doUpkeep();
                    if (getCfg().isTestOnly()) {
                        info(getName() + " in test mode. Upkeep stats:" + upkeepResponse.report(true));
                    }
                } catch (Throwable t) {
                    info("Upkeep failed (" + t.getClass().getSimpleName() + "):" + t.getMessage());
                }

            } catch (InterruptedException e) {
                setStopThread(true); // just in case.
                warn("Upkeep for " + getName() + " interrupted, stopping thread...");
            }
        }
    }
}
