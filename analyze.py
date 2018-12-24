from pandas import *
from scapy.all import *
import seaborn as sns


def analyze(file):
    print("1.5")
    pcap = rdpcap(file)
    print("2")
    # Collect field names from IP/TCP/UDP (These will be columns in DF)
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload', 'payload_raw', 'payload_hex']
    print("3")
    # Create blank DataFrame
    df = DataFrame(columns=dataframe_fields)
    for packet in pcap[IP]:
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])

        field_values.append(packet.time)

        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)

        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        # Add row to DF
        df_append = DataFrame([field_values], columns=dataframe_fields)
        df = concat([df, df_append], axis=0)

    # Reset Index
    df = df.reset_index()
    # Drop old index column
    df = df.drop(columns="index")
    print("4")
    return df


def create_plot(df):
    frequent_address = df['src'].describe()['top']
    # Group by Source Address and Payload Sum
    source_addresses = df.groupby("src")['payload'].sum()
    source_addresses.plot(kind='barh', title="Addresses Sending Payloads", figsize=(8, 5))
    print("5")
    # Group by Destination Address and Payload Sum
    destination_addresses = df.groupby("dst")['payload'].sum()
    destination_addresses.plot(kind='barh', title="Destination Addresses (Bytes Received)", figsize=(8, 5))
    print("6")
    # Group by Source Port and Payload Sum
    source_payloads = df.groupby("sport")['payload'].sum()
    source_payloads.plot(kind='barh', title="Source Ports (Bytes Sent)", figsize=(8, 5))
    print("7")
    # Group by Destination Port and Payload Sum
    destination_payloads = df.groupby("dport")['payload'].sum()
    destination_payloads.plot(kind='barh', title="Destination Ports (Bytes Received)", figsize=(8, 5))

    # groupby("time")['payload'].sum().plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(8,5))
    print("8")
    frequent_address_df = df[df['src'] == frequent_address]
    x = frequent_address_df['payload'].tolist()
    print("9")
    plot = sns.barplot(x="time", y="payload", data=frequent_address_df[['payload', 'time']],
                       label="Total", color="b")
    return plot
