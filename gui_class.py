#https://secdevops.ai/learning-packet-analysis-with-data-science-5356a3340d4e
import sys
from canvas import *
from analyze import *
from gui import *
from P_Sniffer import *
from threading import Thread
from PyQt5 import QtWidgets, QtGui
from numpy import *
import seaborn as sns
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QLineEdit

sns.set(color_codes=True)


class GUI(object):
    def __init__(self):
        super().__init__()
        self.app = QtWidgets.QApplication(sys.argv)
        self.MainWindow = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.MainWindow)
        self.ui.ListView.horizontalScrollBar().setValue(self.ui.ListView.verticalScrollBar().minimum())

        self.ui.DetailView.setColumnCount(1)
        self.ui.actionOpen.triggered.connect(self.select_file)
        self.ui.actionSave.triggered.connect(self.save_file)
        self.ui.actionNew.triggered.connect(self.refresh_session)
        self.ui.actionToggle_FullScreen.triggered.connect(self.toggle_full_screen)
        self.ui.actionAnalyze.triggered.connect(self.analyze_file)
        self.ui.actionSaveAnalyze.triggered.connect(self.save_and_analyze_file)
        self.ui.actionCreateGraph.triggered.connect(self.create_graph)

        self.packets_details = []
        self.packets_summary = []
        self.packets_hex = []

        self.df = None
        self.ui.actionCreateGraph.setEnabled(False)

        self.sniffer = PSniffer()
        self.sniffer.packet_received.connect(self.view_packet)
        self.ui.start_btn.clicked.connect(self.start_sniff)
        self.ui.stop_btn.clicked.connect(self.stop_sniff)
        self.ui.filter_btn.clicked.connect(self.filter)
        self.ui.ListView.itemClicked.connect(self.view_packet_details)
        self.MainWindow.show()
        self.ui.stop_btn.setEnabled(False)
        self.sniff_thread = None

    def view_packet(self, packet_summary, packet_detail, packet_hex):
        '''if packet_summary['ID'] == 0:
            self.http_view.setHidden(False)
            self.ethernet_view.setHidden(False)
            self.ip_view.setHidden(False)
            self.tcp_view.setHidden(False)'''

        new_packet = QtWidgets.QTreeWidgetItem(self.ui.ListView)
        new_packet.setText(0, str(packet_summary['ID']))
        new_packet.setText(1, str(packet_summary['Time']))
        new_packet.setText(2, str(packet_summary['Source']))
        new_packet.setText(3, str(packet_summary['Destination']))
        new_packet.setText(4, str(packet_summary['Protocol']))
        new_packet.setText(5, str(packet_summary['Length']))
        new_packet.setText(6, str(packet_summary['Info']))

        self.packets_summary.append(packet_summary)
        self.packets_details.append(packet_detail)
        self.packets_hex.append(packet_hex)
        if packet_summary['ID'] == 0:
            self.ui.ListView.setCurrentItem(new_packet)
            self.view_packet_details()

    def view_packet_details(self):
        s = self.ui.ListView.selectedItems()
        if s:
            packet_no = s[0].text(0)
            self.ui.DetailView.clear()
            packet_details = self.packets_details[int(packet_no)]
            for protocol in packet_details:
                tmp = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
                tmp.setText(0, self.header_rename(protocol[0]))
                for i in range(1, len(protocol)):
                    tmp2 = QtWidgets.QTreeWidgetItem(tmp)
                    tmp2.setText(0, protocol[i][0] + " : " + protocol[i][1])
            self.ui.NumView.setText(self.packets_hex[int(packet_no)].split("\n\n")[0])
            self.ui.HexView.setText(self.packets_hex[int(packet_no)].split("\n\n")[1])
            self.ui.AscView.setText(self.packets_hex[int(packet_no)].split("\n\n")[2])

    def header_rename(self, header):
        header = header.replace(']', '')
        header = header.replace('[', '')
        header = header.replace('###', '')
        header = header.replace(' ', '')
        if header == 'Ethernet':
            return "Ethernet"
        elif header == 'IP':
            return "Internet Protocol Version 4"
        elif header == 'TCP':
            return 'Transmission Control Protocol'
        elif header == 'UDP':
            return 'User datagram Protocol'
        elif header == 'DNS':
            return 'Domain Name Server'
        elif header == 'Raw':
            return 'Raw'
        else:
            return header

    def start_sniff(self):
        self.sniff_thread = Thread(target=self.sniffer.start_sniffing)
        self.sniff_thread.start()
        self.ui.start_btn.setEnabled(False)
        self.ui.stop_btn.setEnabled(True)
        self.ui.filter_btn.setEnabled(False)

    def stop_sniff(self):
        self.sniffer.stop_sniffing()
        self.ui.start_btn.setEnabled(True)
        self.ui.stop_btn.setEnabled(False)
        self.ui.filter_btn.setEnabled(True)

    def receive_packets(self, sniffed_packets, detailed_packets, summary_packets):
        self.view_packet(sniffed_packets[1])

    def filter(self):
        self.sniffer.filter = self.ui.lineEdit.text()

    def select_file(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self.MainWindow, "Open a File",
                                                          filter="Wireshark capture file (*.pcap;*.pcapng);;All Files (*.*)")
        if file_name[0]:
            self.sniffer.read_pcap_file(file_path=file_name[0])

    def save_file(self):
        file_name = QtWidgets.QFileDialog.getSaveFileName(self.MainWindow, "Save into a File",
                                                          filter="Wireshark capture file (*.pcap;*.pcapng);;All Files (*.*)")
        if file_name[0]:
            self.sniffer.write_into_pcap(file_path_name=file_name[0])

    def refresh_session(self):
        self.ui.DetailView.clear()
        self.ui.ListView.clear()
        self.ui.HexView.clear()
        self.ui.NumView.clear()
        self.ui.AscView.clear()

        self.packets_details.clear()
        self.packets_summary.clear()
        self.packets_hex.clear()

        self.sniffer.refresh()

    def toggle_full_screen(self):
        if self.MainWindow.isFullScreen():
            self.MainWindow.showNormal()
        else:
            self.MainWindow.showFullScreen()

    def analyze_file(self):
        file = QtWidgets.QFileDialog.getOpenFileName(self.MainWindow, "Open a File",
                                                          filter="Wireshark capture file (*.pcap;*.pcapng);;All Files (*.*)")
        self.df = analyze(file[0])
        if self.df is not None:
            self.ui.actionCreateGraph.setEnabled(True)

    def save_and_analyze_file(self):
        file_name = QtWidgets.QFileDialog.getSaveFileName(self.MainWindow, "Save into a File",
                                                          filter="Wireshark capture file (*.pcap;*.pcapng);;All Files (*.*)")
        if file_name[0]:
            self.sniffer.write_into_pcap(file_path_name=file_name[0])
        self.df = analyze(file_name[0])
        if self.df is not None:
            self.ui.actionCreateGraph.setEnabled(True)

    def getChoice(self):
        items = ("Addresses Sending Payloads", "Destination Addresses (Bytes Received)", "Source Ports (Bytes Sent)",
                 "Destination Ports (Bytes Received)", "Time to Bytes")
        item, okPressed = QInputDialog.getItem(self.MainWindow, "Get item", "Type of graph:", items, 0, False)
        if okPressed and item:
            return item

    def create_graph(self):
        item = self.getChoice()
        create_plot(self.df, item)


if __name__ == "__main__":
    temp = GUI()
    sys.exit(temp.app.exec_())
