import com.rundeck.plugin.HttpNotificationPlugin
import spock.lang.Specification

/**
 * Created by rundeck on 12/28/17.
 */
class HttpNotificationPluginSpec extends Specification{

    def "call existing http endpoint"() {
        given:

        def notificator = new HttpNotificationPlugin()

        String remoteUrl="https://outlook.office.com/webhook/79d86a26-f956-4e3a-bc3a-9dc11cc6903f@b1fd7989-50d8-455b-9070-a00d818974ec/IncomingWebhook/8cf770284a124a92a52a39c8f7895eb3/1b958be6-edb8-44db-b423-f8fcafb1a1fe"
        String methodStr = "POST"
        String contentType ="application/json"
        String bodyStr1 = "{\"text\":\"1111111111111wrong 한글은.\"}";
        String bodyStr = new String(bodyStr1.getBytes("UTF-8"),"UTF-8");
        def executionData = [:]
        def config = [remoteUrl:remoteUrl,method:methodStr,contentType:contentType,body:bodyStr]
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
