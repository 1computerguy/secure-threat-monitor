#!/usr/bin/env python3

import os
import pandas as pd

base_path = os.getcwd()
chrome_csv = os.path.join(base_path, 'test_train_data-chrome.csv')
firefox_csv = os.path.join(base_path, 'test_train_data-firefox.csv')
malware_csv = os.path.join(base_path, 'test_train_data-malware.csv')
outfile = os.path.join(base_path, 'test_train_data-all.csv')

combined_csv = pd.concat([pd.read_csv(csv_file, header=0) for csv_file in [chrome_csv, firefox_csv, malware_csv]])

shuffled_csv = combined_csv.sample(frac=1)

shuffled_csv.to_csv(outfile)