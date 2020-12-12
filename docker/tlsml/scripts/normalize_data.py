#!/usr/bin/env python3

from pandas import read_csv
from sklearn.preprocessing import MinMaxScaler
import tensorflow as tf
from tensorflow.keras import layers
from tensorflow.keras import regularizers

scaler = MinMaxScaler()
csv_file = "test_train_data.csv"
dataset = read_csv(csv_file)
normalized_data = scaler.fit_transform(dataset)

ae_input_features = len(dataset.columns)
round_one_hidden_units = 100
round_two_hidden_units = 75
round_three_hidden_units = 50
final_round_output_units = 25

ae_output_features = ae_input_features
ae_learning_rate = 0.01

ae_inputs = tf.keras.Input(shape=(ae_input_features,))
ae_encoded = layers.Dense(round_one_hidden_units, activation='relu',
                    activity_regularizer=regularizers.l1(10e-5))(ae_inputs)
ae_encoded = layers.Dense(round_two_hidden_units, activation='relu',
                    activity_regularizer=regularizers.l1(10e-5))(ae_encoded)
ae_encoded = layers.Dense(round_three_hidden_units, activation='relu',
                    activity_regularizer=regularizers.l1(10e-5))(ae_encoded)
ae_encoded = layers.Dense(final_round_output_units, activation='relu',
                    activity_regularizer=regularizers.l1(10e-5))(ae_encoded)

autoencoder = tf.keras.Model(ae_inputs)