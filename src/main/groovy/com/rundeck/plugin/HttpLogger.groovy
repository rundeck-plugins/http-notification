package com.rundeck.plugin

import com.dtolabs.rundeck.plugins.PluginLogger
import groovy.transform.CompileStatic
import org.slf4j.Logger

@CompileStatic
class HttpLogger implements PluginLogger{

    Logger log

    HttpLogger(Logger log) {
        this.log = log
    }

    @Override
    void log(int level, String message) {
        printMessage(level, message)

    }

    @Override
    void log(int level, String message, Map eventMeta) {
        printMessage(level, message)
    }

    @Override
    void event(String eventType, String message, Map eventMeta) {

    }

    void printMessage(int level, String message){
        switch (level){
            case 0:
                log.error(message)
                break
            case 1:
                log.warn(message)
                break
            case 2:
                log.info(message)
                break
            case 3:
                log.info(message)
                break
            case 4:
                log.debug(message)
                break
            default:
                log.info(message)
                break
        }
    }

}
