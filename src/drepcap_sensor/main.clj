;;;
;;;   Copyright 2014, Frankfurt University of Applied Sciences
;;;
;;;   This software is released under the terms of the Eclipse Public License 
;;;   (EPL) 1.0. You can find a copy of the EPL at: 
;;;   http://opensource.org/licenses/eclipse-1.0.php
;;;

(ns
  ^{:author "Ruediger Gad",
    :doc "Main class."}
  drepcap-sensor.main
  (:use clj-assorted-utils.util
        clj-net-pcap.core
        clj-net-pcap.pcap-data
        clojure.pprint
        clojure.tools.cli)
  (:require (clj-jms-activemq-toolkit [jms :as activemq]))
  (:import (clj_jms_activemq_toolkit ByteArrayWrapper PooledBytesMessageProducer PooledBytesMessageProducer$CompressionMethod)
           (clj_net_pcap ByteArrayHelper Counter ProcessingLoop PacketHeaderDataBean)
           (java.nio ByteBuffer)
           (java.util ArrayList HashMap)
           (java.util.concurrent ArrayBlockingQueue LinkedBlockingQueue)
           (org.jnetpcap.packet PcapPacket))
  (:gen-class))

(def capture-size 96)
(def hot-standby-filter "less 1")

(defn compute-deltas
  [m time-delta delta-cntr]
  (reduce #(assoc %1 (key %2) (float (/ (delta-cntr (keyword (key %2)) (val %2)) time-delta))) {} m))

(defn set-atom-from-string-typesafe
  [s r t]
  (let [v (binding [*read-eval* false] (read-string s))]
    (if (= t (type v))
      (swap! r (fn [_] v)))))

(defn- parse-args [args]
  (cli args
    ["-c" "--compression"
     "Optionally compress the transferred data. Available values: none, lzf, snappy"
     :default "none"]
    ["-d" "--duration"
     "The duration in seconds how long cljSnifferGenerator is run."
     :default -1
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-f" "--filter"
     (str "Pcap filter to be used.")
     :default "less 1"]
    ["-h" "--help" "Print this help." :flag true]
    ["-i" "--interface"
     "Interface on which the packets are captured."
     :default "eth0"]
    ["-q" "--queue-size"
     (str "Size of packet queue."
          "Determines how many packets are captured before a message is sent.")
     :default 100
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-s" "--stat-interval"
     "Interval in milliseconds with which statistics are generated."
     :default 200
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-t" "--topic"
     "Enable debug output."
     :default "default"]
    ["-u" "--url"
     "URL used to connect to the broker."
     :default "tcp://localhost:61616"]
    ["-C" "--cold-standby" "Start in cold standby." :flag true]
    ["-D" "--debug" "Enable debugging." :flag true]
    ["-I" "--id"
     "An identifier that uniquely identifies the sensor instance."
     :default "1"]
    ["-O" "--offset"
     "Offset in microseconds that is added to the timestamp."
     :default 0
     :parse-fn #(Integer. ^java.lang.String %)]
    ["-S" "--silent" "Omit most command line output." :flag true]))

(defn -main [& args]
  (let [cli-args (parse-args args)
        arg-map (cli-args 0)
        extra-args (cli-args 1)
        help-string (cli-args 2)]
    (when (arg-map :help)
      (println help-string)
      (System/exit 0))
    (println "Starting drepcap-sensor using the following options:")
    (pprint arg-map)
    (pprint extra-args)
    (let [id (arg-map :id)
          compression (arg-map :compression)
          debug (atom (arg-map :debug))
          offset (atom (arg-map :offset))
          silent (atom (arg-map :silent))
          queue-size (arg-map :queue-size)
          run-duration (arg-map :duration)
          cold-standby (ref (arg-map :cold-standby))
          running (ref true)
          url (arg-map :url)
          topic-infix "raw"
          topic-prefix (if (= (arg-map :topic) "default")
                         (str "/topic/pcap.single." topic-infix "." id)
                         (arg-map :topic))
          _ (println "Using broker at" url "with topic prefix" topic-prefix "and queue size" queue-size)
          cntr-sent (Counter.) cntr-dropped (Counter.) cntr-queued (Counter.) cntr-failed (Counter.)
          packet-process-fn (fn [^ByteBuffer buf] (if (.hasArray buf) (ByteArrayWrapper. (.array buf))))
          data-queue (ArrayBlockingQueue. *queue-size*)
          forwarder-fn (fn [obj]
                         (try
                           (if (and (not (nil? obj))
                                    (< (.size data-queue) *queue-size*))
                             (let [data (packet-process-fn obj)]
                               (if (.offer data-queue data)
                                 (.inc cntr-queued)
                                 (.inc cntr-dropped)))
                             (.inc cntr-dropped))
                           (catch Exception e
                             (.inc cntr-failed))))
          interface (arg-map :interface)
          cljnetpcap (ref (if-not @cold-standby
                            (binding [clj-net-pcap.pcap/*snap-len* capture-size
                                      clj-net-pcap.core/*emit-raw-data* true
                                      clj-net-pcap.core/*forward-exceptions* @debug]
                              (create-and-start-online-cljnetpcap forwarder-fn interface (arg-map :filter)))))
          data-topic (str topic-prefix ".data")
          ^PooledBytesMessageProducer data-producer (activemq/create-pooled-bytes-message-producer url data-topic queue-size)
          _ (condp = compression
              "lzf" (doto data-producer
                      (.setCompress true)
                      (.setCompressionMethod PooledBytesMessageProducer$CompressionMethod/Lzf))
              "snappy" (doto data-producer
                         (.setCompress true)
                         (.setCompressionMethod PooledBytesMessageProducer$CompressionMethod/Snappy))
              nil)
          monitor-producer (activemq/create-producer  url (str topic-prefix ".monitor"))
          command-topic (str topic-prefix ".command")
          command-producer (activemq/create-producer url command-topic)
          send-error-msg activemq/send-error-msg
          time-tmp (ref (System/currentTimeMillis))
          delta-cntr (delta-counter) total-delta-cntr (delta-counter)
          stats-fn (fn []
                     (if (and (not @cold-standby) @running)
                       (let [time-delta (/ (- (System/currentTimeMillis) @time-tmp) 1000)
                             _ (dosync
                                 (ref-set time-tmp (System/currentTimeMillis)))
                             pcap-stats (cljnetpcap-stats @cljnetpcap)
                             absolute-stats-map (merge
                                                  {"main-sent" (.value cntr-sent) "main-failed" (.value cntr-failed)
                                                   "main-dropped" (.value cntr-dropped) "main-queued" (.value cntr-queued)}
                                                   ;;; Packets receivd on "lo" are reported twice. Take care of that here.
                                                   ;;; The packet processing is not affected by this peculiarity.
                                                   (if (= interface "lo")
                                                     (update-in pcap-stats ["recv"] #(/ % 2))
                                                     pcap-stats))
                             absolute-total-stats-map (assoc
                                                        {}
                                                        "received" (absolute-stats-map "recv")
                                                        "sent" (absolute-stats-map "main-sent")
                                                        "dropped" (reduce-selected-map-entries absolute-stats-map + ["main-dropped" "drop" "ifdrop" "out-dropped"])
                                                        "failed" (reduce-selected-map-entries absolute-stats-map + ["main-failed" "forwarder-faild"]))
                             relative-stats-map (compute-deltas absolute-stats-map time-delta delta-cntr)
                             relative-total-stats-map (compute-deltas absolute-total-stats-map time-delta delta-cntr)
                             stats-map {"absolute" absolute-stats-map "relative" relative-stats-map
                                        "absolute-total" absolute-total-stats-map "relative-total" relative-total-stats-map}]
                         (when-not @silent
                           (println stats-map))
                         (monitor-producer (str stats-map)))
                       (let [msg "cold-standby"]
                         (if-not @silent
                           (println msg))
                         (monitor-producer msg))))
          send-fn #(try
                     (let [^ByteArrayWrapper obj (.take data-queue)]
                       (.send data-producer obj)
                       (.inc cntr-sent))
                     (catch Exception e
                       (when @running
                         (.printStackTrace e)
                         (.inc cntr-failed))))
          send-thread (doto (ProcessingLoop. send-fn)
                        (.setName "SendThread") (.setDaemon true) (.start))
          stats-out-executor (executor)
          _ (run-repeat stats-out-executor stats-fn (arg-map :stat-interval))
          hot-standby? #(= (get-filters @cljnetpcap) [hot-standby-filter])
          send-cold-standby-state #(command-producer (str "reply cold-standby " @cold-standby))
          send-hot-standby-state #(if @cold-standby
                                   (command-producer (str "reply hot-standby true"))
                                   (command-producer (str "reply hot-standby " (hot-standby?))))
          send-standby-states (fn []
                               (send-cold-standby-state)
                               (send-hot-standby-state))
          cmd-rcvd-fn (fn [msg]
                        (if (= (type msg) java.lang.String)
                          (condp (fn [v c] (.startsWith c v)) msg
                            "reply" nil ; We ignore replies.
                            "command"
                              (let [split-cmd (subvec (clojure.string/split msg #" ") 1)
                                    cmd (first split-cmd)
                                    args (clojure.string/join " " (rest split-cmd))]
                                (println "Got command:" cmd "and args:" args)
                                (if-not @cold-standby
                                  (condp = cmd
                                    "activate-from-hot-standby" (when (hot-standby?)
                                                                  (remove-all-filters @cljnetpcap)
                                                                  (send-hot-standby-state))
                                    "add-filter" (try
                                                   (add-filter @cljnetpcap args)
                                                   (command-producer "reply success Filter added.")
                                                   (catch Exception e
                                                     (send-error-msg command-producer (str "Error while adding filter: " e))))
                                    "cold-standby" (do
                                                     (dosync (ref-set cold-standby true))
                                                     (stop-cljnetpcap @cljnetpcap)
                                                     (dosync (ref-set cljnetpcap nil))
                                                     (send-standby-states))
                                    "get-filters" (command-producer (str "reply pcap-filters " (get-filters @cljnetpcap)))
                                    "get-offset" (command-producer (str "reply offset " @offset))
                                    "get-silent" (command-producer (str "reply silent " @silent))
                                    "get-standby-states" (send-standby-states)
                                    "hot-standby" (do
                                                    (try
                                                      (remove-all-filters @cljnetpcap)
                                                      (add-filter @cljnetpcap hot-standby-filter)
                                                      (catch Exception e
                                                        (send-error-msg command-producer (str "Error error while switching to hot standby: " e))))
                                                    (send-hot-standby-state))
                                    "replace-filter" (let [filters (clojure.string/split args #" with-filter ")]
                                                       (replace-filter @cljnetpcap (first filters) (second filters)))
                                    "remove-all-filters" (remove-all-filters @cljnetpcap)
                                    "remove-last-filter" (remove-last-filter @cljnetpcap)
                                    "set-offset" (let [v (binding [*read-eval* false] (read-string args))]
                                                   (if (= java.lang.Long) v)
                                                     (swap! offset (fn [_] v)))
                                    "set-offset" (set-atom-from-string-typesafe args silent java.lang.Long)
                                    "set-silent" (set-atom-from-string-typesafe args silent java.lang.Boolean)
                                    (send-error-msg command-producer (str "Unknown command received: " cmd " Args: " args)))
                                  (condp = cmd
                                    "activate-from-cold-standby" (try
                                                                   (let [pcap-args (clojure.string/split args #" ")
                                                                         cljnetpcap-tmp (binding [clj-net-pcap.pcap/*snap-len* capture-size
                                                                                                  clj-net-pcap.core/*emit-raw-data* true
                                                                                                  clj-net-pcap.core/*forward-exceptions* @debug]
                                                                                          (create-and-start-online-cljnetpcap 
                                                                                            forwarder-fn
                                                                                            (first pcap-args)
                                                                                            (clojure.string/join " " (rest pcap-args))))]
                                                                     (dosync (ref-set cljnetpcap cljnetpcap-tmp))
                                                                     (dosync (ref-set cold-standby false))
                                                                     (send-standby-states))
                                                                   (catch Exception e
                                                                     (send-error-msg command-producer (str "Error activating from cold standby: " cmd " Args: " args " Exception: " (.getMessage e)))))
                                    "get-silent" (command-producer (str "reply silent " @silent))
                                    "get-standby-states" (send-standby-states)
                                    "set-silent" (set-atom-from-string-typesafe args silent java.lang.Boolean)
                                    (send-error-msg command-producer (str "Unknown command received (cold-standby): " cmd " Args: " args)))))
                            (send-error-msg command-producer (str "Received invalid message: " msg)))
                          (send-error-msg
                            command-producer
                            (str "Received command message of wrong data type: " (type msg) " "
                                 "Received data is: " msg))))
          command-consumer (activemq/create-consumer url command-topic cmd-rcvd-fn)
          shutdown-fn (fn [] 
                        (println "Shutting down...")
                        (println "Sent:" (.value cntr-sent) "Failed:" (.value cntr-failed))
                        (dosync (ref-set running false))
                        (shutdown-now stats-out-executor)
                        (when-not @cold-standby
                          (println (cljnetpcap-stats @cljnetpcap))
                          (stop-cljnetpcap @cljnetpcap))
                        (.interrupt send-thread)
                        (command-consumer :close)
                        (command-producer :close)
                        (.close data-producer)
                        (monitor-producer :close))]
      (if (> run-duration 0)
        (do
          (println "Will automatically shut down in" run-duration "seconds.")
          (run-once (executor) shutdown-fn (* 1000 run-duration)))
        (do
          (println "drepcap-sensor started.\nType \"q\" followed by <Return> to quit: ")
          (while (not= "q" (read-line))
            (println "Type \"q\" followed by <Return> to quit: "))
          (shutdown-fn))))))

