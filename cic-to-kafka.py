import os
import pandas as pd
import pyfiglet
import datetime
import json
import uuid
import json
from os import listdir
from os.path import isfile, join
import os
from kafka import KafkaProducer
from threading import Thread
import subprocess


def print_banner():
    ascii_banner = pyfiglet.figlet_format("CICFlowMeter")
    print(ascii_banner)


def traffic_sniffing(config):
    """
    This function is responsible for sniffing the network traffic, using the timeout and tcpdump software packages.
    """

    print("\n--------------\nNew Network Traffic Capturing\n")
    
    try:
        os.remove('./labelled-pcap/capture_temp.pcap')
    except OSError as error:
        print(error)
        pass

    time = config["General"]["ONLINE_CAPTURE_DURATION"]
    interface = config["General"]["ONLINE_CAPTURE_INTERFACE"]

    if "ONLINE_CAPTURE_PORTS_BLACKLIST" in config["General"]:
        ports = "\'("
        for i in config["General"]["ONLINE_CAPTURE_PORTS_BLACKLIST"]:
            ports = ports + str(i) + ' or '
        ports = ports[:-4] + ")\'"
        os.system("timeout " + time + " tcpdump -i " + interface + " not port " + ports + " -w ./labelled-pcap/capture_temp.pcap")
        os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")

    elif "ONLINE_CAPTURE_PORTS_WHITELIST" in config["General"]:
        ports = "\'("
        for i in config["General"]["ONLINE_CAPTURE_PORTS_WHITELIST"]:
            ports = ports + str(i) + ' or '
        ports = ports[:-4] + ")\'"
        os.system("timeout " + time + " tcpdump -i " + interface + " port " + ports + " -w ./labelled-pcap/capture_temp.pcap")
        os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")
    else:
        os.system("timeout " + time + " tcpdump -i " + interface + " -w ./labelled-pcap/capture_temp.pcap")
        os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")

    return 'capture_temp.pcap'


def cicflowmeter(pcap):
    """
    This function is responsible for generating TCP/IP network flows, using CICFlowMeter.
    """

    print("\n--------------\nTCP/TCP Network Flow Statistics Generation\n")

    try:
        os.remove("./labelled-pcap/" + pcap + "_Flow.csv")
    except OSError as error:
        print(error)
        pass

    p = subprocess.Popen(["./cfm", "../../labelled-pcap/"+pcap, "../../unlabelled-csv"], cwd="./cicflowmeter/bin")
    p.wait()
    os.system("chmod 777 ./unlabelled-csv/" + pcap + "_Flow.csv")
    return "./unlabelled-csv/" + pcap + "_Flow.csv"


def transmit_to_kafka(flowsCSV_df, KAFKA_PRODUCER, topic):
    
    for counter in range(len(flowsCSV_df)):
        flowsCSV_df.loc[counter, "Timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()  # Covert timestamp to UTC
        flowJson = flowsCSV_df.iloc[counter].to_json()

        flowJson = json.loads(flowJson)
        flowJson["id"] = uuid.uuid4().hex

        flowJson = json.dumps(flowJson).encode('utf-8')

        KAFKA_PRODUCER.send(topic, flowJson)


if __name__ == "__main__":
    
    os.system("clear")
    print_banner()

    ## Load configuration file
    config = None
    with open('config.json') as f:
        config = json.load(f)

    ## Initialise Kafka broker (in case Kafka is enabled in the config file)
    KAFKA_PRODUCER = None
    if config["General"]["OUTPUT_KAFKA"]:
        if config["Kafka"]["KAFKA_SECURITY"] == "SASL_PLAINTEXT":
            KAFKA_PRODUCER = KafkaProducer(
                bootstrap_servers='[{0}:{1}]'.format(config["Kafka"]["KAFKA_HOST"], config["Kafka"]["KAFKA_PORT"]),
                security_protocol='SASL_PLAINTEXT',
                sasl_mechanism='PLAIN',
                sasl_plain_username=config["Kafka"]["KAFKA_SASL_USERNAME"],
                sasl_plain_password=config["Kafka"]["KAFKA_SASL_PASSWORD"],
            )
        elif config["Kafka"]["KAFKA_SECURITY"] == "SSL":
            KAFKA_PRODUCER = KafkaProducer(
                bootstrap_servers='[{0}:{1}]'.format(config["Kafka"]["KAFKA_HOST"], config["Kafka"]["KAFKA_PORT"]),
                security_protocol='SSL',
                ssl_check_hostname=False,
                ssl_cafile=config["Kafka"]["KAFKA_CA"],
                ssl_certfile=config["Kafka"]["KAFKA_CERT"],
                ssl_keyfile=config["Kafka"]["KAFKA_KEY"],
                ssl_password=config["Kafka"]["KAFKA_PASSWORD"]
            )
        else:
            KAFKA_PRODUCER = KafkaProducer(bootstrap_servers='[{0}:{1}]'.format(config["Kafka"]["KAFKA_HOST"], config["Kafka"]["KAFKA_PORT"]))

    if config["General"]["OPERATION_MODE"] == "ONLINE": 
        while True:
            pathPcapFile = traffic_sniffing(config)
            cicflowmeter_flows_CSV_file = cicflowmeter(pathPcapFile)            

            if config["General"]["OUTPUT_KAFKA"]:
                cicflowmeter_flowsCSV_df = pd.read_csv(cicflowmeter_flows_CSV_file)
                Thread(target=transmit_to_kafka, args=(cicflowmeter_flowsCSV_df, KAFKA_PRODUCER, config["Kafka"]["KAFKA_TOPIC_CICFLOWMETER"])).start()


    elif config["General"]["OPERATION_MODE"] == "OFFLINE":

        PCAP_FILES = config["General"]["OFFLINE_PCAP_FILES"]
        if not PCAP_FILES:
            PCAP_FILES = [f for f in listdir('./labelled-pcap/') if isfile(join('./labelled-pcap/', f))]

        for pcap in PCAP_FILES:
            cicflowmeter_flows_CSV_file = cicflowmeter(pcap)
            if config["General"]["OUTPUT_KAFKA"]:
                cicflowmeter_flowsCSV_df = pd.read_csv(cicflowmeter_flows_CSV_file)
                Thread(target=transmit_to_kafka, args=(cicflowmeter_flowsCSV_df, KAFKA_PRODUCER, config["Kafka"]["KAFKA_TOPIC_CICFLOWMETER"])).start()