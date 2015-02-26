(defproject drepcap-sensor "1.0.0"
  :description "drepcap-sensor sniffs network traffic and sends the captured data to a JMS topic."
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/tools.cli "0.2.4"]
                 [fg-netzwerksicherheit/clj-jms-activemq-toolkit "1.0.0"]
                 [clj-net-pcap "1.6.9995"]
                 [clj-assorted-utils "1.7.0"]]
  :aot :all
  :global-vars {*warn-on-reflection* true}
  :license {:name "Eclipse Public License (EPL) - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo
            :comments "This is the same license as used for Clojure."}
  :main drepcap-sensor.main
)
