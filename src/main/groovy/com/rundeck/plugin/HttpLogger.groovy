package com.rundeck.plugin

import com.dtolabs.rundeck.plugins.PluginLogger
import org.slf4j.Logger

class HttpLogger implements PluginLogger{

    Logger log

    HttpLogger(Logger log) {
        this.log = log
    }

    @Override
    void log(int level, String message) {
        log.info(message)
    }

    @Override
    void log(int level, String message, Map eventMeta) {
        log.info(message)
    }

    @Override
    void event(String eventType, String message, Map eventMeta) {

    }
}
