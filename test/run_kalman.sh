#sudo hcitool -i hci0 lescan --duplicates > /dev/null | sudo btmon |./scan-plot.py --group rtls_arman_ble_19_9_97_1 --server http://127.0.0.1:8072 --time 1 --interface hci0 --color y &
#sudo hcitool -i hci1 lescan --duplicates > /dev/null | sudo btmon |./scan-plot.py --group rtls_arman_ble_19_9_97_1 --server http://127.0.0.1:8072 --time 1 --interface hci1 --color r &
#sudo hcitool -i hci2 lescan --duplicates > /dev/null | sudo btmon |./scan-plot.py --group rtls_arman_ble_19_9_97_1 --server http://127.0.0.1:8072 --time 1 --interface hci2 --color b &
sudo hcitool -i hci1 lescan --duplicates > /dev/null | hcitool -i hci2 lescan --duplicates > /dev/null | sudo btmon |./scan-plot_combined.py --group rtls_arman_ble_19_9_97_1 --server http://127.0.0.1:8072 --time 1 --interface hci[12] --color g &
sudo hcitool -i hci1 lescan --duplicates > /dev/null | hcitool -i hci2 lescan --duplicates > /dev/null | sudo btmon |./scan-plot_combined_kalman.py --group rtls_arman_ble_19_9_97_1 --server http://127.0.0.1:8072 --time 1 --interface hci[12] --color y &