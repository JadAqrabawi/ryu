sudo systemctl restart NetworkManager

ryu-manager ryu_controller.py

sudo python3 mininet_sdn_script.py --controller=remote,ip=<10.0.0.1>,port=6633


