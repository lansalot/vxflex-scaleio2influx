# vxflex-scaleio2influx
A powershell script to query the ScaleIO/VxFlex REST API, and send to InfluxDB for use with Grafana etc

Requirements
- Powershell
- ScaleIO or VxFlex, with the EMC Gateway service configured and available
- An InfluxDB instance
- (optional) Grafana

# Configuration

## ScaleIO/VxFlex Gateway

Install the gateway service as per your configuration instructions. For the sake of your sanity and peace of mind, create a read-only monitoring account in ScaleIO/VxFlex.

coming soon...

## Install and configure InfluxDB

If you're of a linux preference, just install the influxdb-server package with your appropriate packaging tool. If you need a decent video to help, check out this [link](https://www.youtube.com/watch?v=tI7B7AQFEJk])

## Configure the script's supporting JSON file

Should be self-explanatory

## Run the script

You may wish to put this as a computer startup script, and set it to run indefinitely

## Import the Grafana dashboard

- Create a datasource in Grafana called InfluxDB
- Import the dashboard
