# vxflex-scaleio2influx
A powershell script to query the ScaleIO/VxFlex REST API, and send to InfluxDB for use with Grafana etc

Requirements
- Powershell wintel (core or standard) or *nix (core)
- ScaleIO or VxFlex, with the EMC Gateway service configured and available
- An [InfluxDB](https://www.influxdata.com/) instance
- (optional) [Grafana](https://grafana.com/)

# Configuration

## ScaleIO/VxFlex Gateway

Install the gateway service as per your configuration instructions. For the sake of your sanity and peace of mind, create a read-only monitoring account in ScaleIO/VxFlex.

## Install and configure InfluxDB

If you're of a linux preference, just install the influxdb-server package with your appropriate packaging tool. If you need a decent video to help, check out this [link](https://www.youtube.com/watch?v=tI7B7AQFEJk])

- Create a database to match the influx.database.name in the JSON file
~~~~
> create database GRAFANA
> create user grafana with password 'Str00ngpw!'
> grant all on grafana to grafana 
~~~~

## Configure the script's supporting JSON file

Should be self-explanatory but roughly you need to supply:
- IP addresses and credentials of gateway ("enabled" false if you wish to note it on the config, but not poll it)
- IP address and credentials of influxdb
- poolmetrics - a strong starting point is included, tweak if you wish to add more or can do without some
- in "alerts", provide your local SMTP server and basic information. If you use authentication, add the required fields as they are passed verbatim to Send-MailMessage

## Run the script

You may wish to put this as a computer startup script, and set it to run indefinitely

## Import the Grafana dashboard

- Create a datasource in Grafana called InfluxDB
- Import the dashboard
- adjust the datasource accordingly
