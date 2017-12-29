import com.rundeck.plugin.HttpNotificationPlugin
import spock.lang.Specification

/**
 * Created by rundeck on 12/28/17.
 */
class HttpNotificationPluginSpec extends Specification{

    def "call existing http endpoint"() {
        given:

        def notificator = new HttpNotificationPlugin()

        String remoteUrl="http://google.com"
        String methodStr = "GET"
        String contentType ="text/html"
        def executionData = [:]
        def config = [remoteUrl:remoteUrl,method:methodStr,contentType:contentType]
        String trigger ="success"

        when:
        def result = notificator.postNotification(trigger,executionData,config)

        then:

        result == true
    }

    def "call bad http endpoint"() {
        given:

        def notificator = new HttpNotificationPlugin()

        String remoteUrl="http://rundeck.org"
        String methodStr = "PUT"
        String contentType ="text/html"
        def executionData = [:]
        def config = [remoteUrl:remoteUrl,method:methodStr,contentType:contentType,timeout:0]
        String trigger ="fail"

        when:
        def result = notificator.postNotification(trigger,executionData,config)

        then:

        result == false


    }

    def "call not existing http endpoint"() {
        given:

        def notificator = new HttpNotificationPlugin()

        String remoteUrl="http://123.com"
        String methodStr = "PUT"
        String contentType ="text/html"
        def executionData = [:]
        def config = [remoteUrl:remoteUrl,method:methodStr,contentType:contentType,timeout:0]
        String trigger ="fail"

        when:
        def result = notificator.postNotification(trigger,executionData,config)

        then:

        result == false


    }


}
