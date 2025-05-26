import matplotlib.pyplot as plt

from tegrastats_data import *

def timestamp_to_seconds(ts):
    minutes, seconds = ts.split(":")
    return int(minutes) * 60 + float(seconds)

########### Plotting #############

# Plot Simple
title_simple = "Hardware Metrics: TLS 1.3"
filename_simple = "Tegrastats_simple"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in simple_timestamps], simple_cpu_usage, label="CPU usage", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in simple_timestamps], simple_gpu_usage, label="GPU usage", color='red')
plt.plot([timestamp_to_seconds(ts) for ts in simple_timestamps], simple_ram_usage, label="RAM usage", color='green')
plt.plot([timestamp_to_seconds(ts) for ts in simple_timestamps], [round(x / 20.0 * 100, 1) for x in simple_power_consumption], label="Power Consumption ", color='orange')

plt.xlabel("Timestamp (s)")
plt.ylabel("Usage Percentage (%)")
plt.title(title_simple)


# # Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(simple_timestamps), step),
#            labels=[simple_timestamps[i] for i in range(0, len(simple_timestamps), step)],
#            rotation=45)  # rotate for better readability



plt.axvline(x=timestamp_to_seconds("57:12.0"), color='yellow', linestyle='--', linewidth=1.5, label='TLS 1.3 and Hybrid Handshake')

plt.axvline(x=timestamp_to_seconds("57:54.1"), color='green', linestyle='--', linewidth=1.5, label='image 1')
plt.axvline(x=timestamp_to_seconds("57:56.2"), color='green', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("58:21.4"), color='orange', linestyle='--', linewidth=1.5, label='image 2')
plt.axvline(x=timestamp_to_seconds("58:23.5"), color='orange', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("58:47.7"), color='purple', linestyle='--', linewidth=1.5, label='image 3')
plt.axvline(x=timestamp_to_seconds("58:49.7"), color='purple', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("59:18.9"), color='black', linestyle='--', linewidth=1.5, label='video')
plt.axvline(x=timestamp_to_seconds("59:25.2"), color='black', linestyle='--', linewidth=1.5)

plt.grid(True)
plt.legend()
plt.tight_layout()

plt.savefig("./plots/" + filename_simple + ".png")


###################
# Plot RTT kyber512
###################
title_kyber512 = "Hardware Metrics: Kyber512"
filename_kyber512 = "Tegrastats_kyber512"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in kyber512_timestamps], kyber512_cpu_usage, label="CPU usage", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in kyber512_timestamps], kyber512_gpu_usage, label="GPU usage", color='red')
plt.plot([timestamp_to_seconds(ts) for ts in kyber512_timestamps], kyber512_ram_usage, label="RAM usage", color='green')
plt.plot([timestamp_to_seconds(ts) for ts in kyber512_timestamps], [round(x / 20.0 * 100, 1) for x in kyber512_power_consumption], label="Power Consumption ", color='orange')

# plt.axvline(x=timestamp_to_seconds("06:51.0"), color='red', linestyle='--', linewidth=1.5, label='ICARUS Initiation')

plt.axvline(x=timestamp_to_seconds("06:10.8"), color='yellow', linestyle='--', linewidth=1.5, label='TLS 1.3 and Hybrid Handshake')
plt.axvline(x=timestamp_to_seconds("06:10.9"), color='yellow', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("07:11.0"), color='green', linestyle='--', linewidth=1.5, label='image 1')
plt.axvline(x=timestamp_to_seconds("07:16.6"), color='green', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("07:36.6"), color='orange', linestyle='--', linewidth=1.5, label='image 2')
plt.axvline(x=timestamp_to_seconds("07:46.6"), color='orange', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("08:02.3"), color='purple', linestyle='--', linewidth=1.5, label='image 3')
plt.axvline(x=timestamp_to_seconds("08:06.9"), color='purple', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("08:22.0"), color='black', linestyle='--', linewidth=1.5, label='video')
plt.axvline(x=timestamp_to_seconds("08:38.1"), color='black', linestyle='--', linewidth=1.5)

plt.xlabel("Timestamp (s)")
plt.ylabel("Usage Percentage (%)")
plt.title(title_kyber512)
# # Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(kyber512_timestamps), step),
#            labels=[kyber512_timestamps[i] for i in range(0, len(kyber512_timestamps), step)],
#            rotation=45)  # rotate for better readability

plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("./plots/" + filename_kyber512 + ".png")


###################
# Plot RTT kyber768
###################
title_kyber768 = "Hardware Metrics: Kyber768"
filename_kyber768 = "Tegrastats_kyber768"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in kyber768_timestamps], kyber768_cpu_usage, label="CPU usage", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in kyber768_timestamps], kyber768_gpu_usage, label="GPU usage", color='red')
plt.plot([timestamp_to_seconds(ts) for ts in kyber768_timestamps], kyber768_ram_usage, label="RAM usage", color='green')
plt.plot([timestamp_to_seconds(ts) for ts in kyber768_timestamps], [round(x / 20.0 * 100, 1) for x in kyber768_power_consumption], label="Power Consumption ", color='orange')

plt.axvline(x=timestamp_to_seconds("19:45.2"), color='yellow', linestyle='--', linewidth=1.5, label='TLS 1.3 and Hybrid Handshake')
plt.axvline(x=timestamp_to_seconds("19:45.3"), color='yellow', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("20:40.3"), color='green', linestyle='--', linewidth=1.5, label='image 1')
plt.axvline(x=timestamp_to_seconds("20:45.3"), color='green', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("21:05.4"), color='orange', linestyle='--', linewidth=1.5, label='image 2')
plt.axvline(x=timestamp_to_seconds("21:10.1"), color='orange', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("21:25.1"), color='purple', linestyle='--', linewidth=1.5, label='image 3')
plt.axvline(x=timestamp_to_seconds("21:29.2"), color='purple', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("21:59.6"), color='black', linestyle='--', linewidth=1.5, label='video')
plt.axvline(x=timestamp_to_seconds("22:30.8"), color='black', linestyle='--', linewidth=1.5)



plt.xlabel("Timestamp (s)")
plt.ylabel("Usage Percentage (%)")
plt.title(title_kyber768)
# # Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(kyber768_timestamps), step),
#            labels=[kyber768_timestamps[i] for i in range(0, len(kyber768_timestamps), step)],
#            rotation=45)  # rotate for better readability

plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("./plots/" + filename_kyber768 + ".png")

###################
# Plot RTT kyber1024
###################
title_kyber1024 = "Hardware Metrics: Kyber1024"
filename_kyber1024 = "Tegrastats_kyber1024"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in kyber1024_timestamps], kyber1024_cpu_usage, label="CPU usage", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in kyber1024_timestamps], kyber1024_gpu_usage, label="GPU usage", color='red')
plt.plot([timestamp_to_seconds(ts) for ts in kyber1024_timestamps], kyber1024_ram_usage, label="RAM usage", color='green')
plt.plot([timestamp_to_seconds(ts) for ts in kyber1024_timestamps], [round(x / 20.0 * 100, 1) for x in kyber1024_power_consumption], label="Power Consumption ", color='orange')

plt.axvline(x=timestamp_to_seconds("30:58.5"), color='yellow', linestyle='--', linewidth=1.5, label='TLS 1.3 and Hybrid Handshake')
plt.axvline(x=timestamp_to_seconds("30:58.6"), color='yellow', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("31:48.7"), color='green', linestyle='--', linewidth=1.5, label='image 1')
plt.axvline(x=timestamp_to_seconds("31:54.1"), color='green', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("32:24.2"), color='orange', linestyle='--', linewidth=1.5, label='image 2')
plt.axvline(x=timestamp_to_seconds("32:32.4"), color='orange', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("32:47.6"), color='purple', linestyle='--', linewidth=1.5, label='image 3')
plt.axvline(x=timestamp_to_seconds("33:03.6"), color='purple', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("33:08.8"), color='black', linestyle='--', linewidth=1.5, label='video')
plt.axvline(x=timestamp_to_seconds("33:32.5"), color='black', linestyle='--', linewidth=1.5)



plt.xlabel("Timestamp (s)")
plt.ylabel("Usage Percentage (%)")
plt.title(title_kyber1024)
# # Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(kyber1024_timestamps), step),
#            labels=[kyber1024_timestamps[i] for i in range(0, len(kyber1024_timestamps), step)],
#            rotation=45)  # rotate for better readability

plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("./plots/" + filename_kyber1024 + ".png")



##########################
# Plotting CPU Usage
##########################

