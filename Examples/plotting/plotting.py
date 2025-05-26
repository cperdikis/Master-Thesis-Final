import matplotlib.pyplot as plt
import numpy as np
from rtt_data import *
from scipy.stats import norm, expon, ttest_ind
import seaborn as sns

def freedman_diaconis_bins(data):
    data = np.asarray(data)
    n = len(data)

    if n < 2:
        raise ValueError("Data must contain at least two values.")

    q75, q25 = np.percentile(data, [75 ,25])
    iqr = q75 - q25

    if iqr == 0:
        raise ValueError("IQR is zero — data might be constant.")

    bin_width = 2 * iqr / (n ** (1/3))
    num_bins = int(np.ceil((data.max() - data.min()) / bin_width))

    return num_bins, bin_width

def timestamp_to_seconds(ts):
    minutes, seconds = ts.split(":")
    return int(minutes) * 60 + float(seconds)

###### Exponential distribution fit
###### TLS1.3

rtt_client = np.array(kyber1024_client_rtts)
rtt_server = np.array(kyber1024_server_rtts)

t_stat, p_value = ttest_ind(rtt_client, rtt_server, equal_var=False)

# Display results
print("For TLS1.3")
print(f"T-statistic: {t_stat:.4f}")
print(f"P-value: {p_value:.4f}")

# Interpret
alpha = 0.05
if p_value < alpha:
    print("Result: Reject the null hypothesis (means are significantly different)")
else:
    print("Result: Accept the null hypothesis (no significant difference between means)")

# Fit exponential distribution: returns (loc, scale), where scale = 1/lambda
loc_c, scale_c = expon.fit(rtt_client, floc=0)
loc_s, scale_s = expon.fit(rtt_server, floc=0)

# x range for plotting the fitted distribution
x = np.linspace(min(rtt_client.min(), rtt_server.min()),
                max(rtt_client.max(), rtt_server.max()), 100)

bin_num_client,bin_width_client = freedman_diaconis_bins(simple_client_rtts)
bin_num_server,bin_width_server = freedman_diaconis_bins(simple_server_rtts)
# Create histogram bins
bins = np.linspace(min(rtt_client.min(), rtt_server.min()),
                   max(rtt_client.max(), rtt_server.max()), 90)

# Plot normalized histograms (PDF approximation)
plt.figure(figsize=(8, 5))
plt.hist(rtt_client, bins=bins, density=True, histtype='step', label='Client', color='blue')
plt.hist(rtt_server, bins=bins, density=True, histtype='step', label='Server', color='red')

# Plot fitted exponential PDFs
plt.plot(x, expon.pdf(x, loc=loc_c, scale=scale_c), 'b--', label=f'Client Exp Fit (λ={1/scale_c:.2f})', linewidth=0.8)
plt.plot(x, expon.pdf(x, loc=loc_s, scale=scale_s), 'r--', label=f'Server Exp Fit (λ={1/scale_s:.2f})', linewidth=0.8)


plt.xlabel('RTT (ms)')
plt.ylabel('Empirical Probability')
plt.title('Empirical Probability Distribution of RTT: TLS 1.3')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("./plots/TLS1.3_exponential_fit.png")

############# Kyber 512
rtt_client = np.array(kyber512_client_rtts)
rtt_server = np.array(kyber512_server_rtts)

t_stat, p_value = ttest_ind(rtt_client, rtt_server, equal_var=False)

# Display results
print("For Kyber512")
print(f"T-statistic: {t_stat:.4f}")
print(f"P-value: {p_value:.4f}")

# Interpret
alpha = 0.05
if p_value < alpha:
    print("Result: Reject the null hypothesis (means are significantly different)")
else:
    print("Result: Accept the null hypothesis (no significant difference between means)")

# Fit exponential distribution: returns (loc, scale), where scale = 1/lambda
loc_c, scale_c = expon.fit(rtt_client, floc=0)
loc_s, scale_s = expon.fit(rtt_server, floc=0)

# x range for plotting the fitted distribution
x = np.linspace(min(rtt_client.min(), rtt_server.min()),
                max(rtt_client.max(), rtt_server.max()), 100)
# Create histogram bins
bins = np.linspace(min(rtt_client.min(), rtt_server.min()),
                   max(rtt_client.max(), rtt_server.max()), 90)

# Plot normalized histograms (PDF approximation)
plt.figure(figsize=(8, 5))
plt.hist(rtt_client, bins=bins, density=True, histtype='step', label='Client', color='blue')
plt.hist(rtt_server, bins=bins, density=True, histtype='step', label='Server', color='red')

# Plot fitted exponential PDFs
plt.plot(x, expon.pdf(x, loc=loc_c, scale=scale_c), 'b--', label=f'Client Exp Fit (λ={1/scale_c:.2f})', linewidth=0.8)
plt.plot(x, expon.pdf(x, loc=loc_s, scale=scale_s), 'r--', label=f'Server Exp Fit (λ={1/scale_s:.2f})', linewidth=0.8)


plt.xlabel('RTT (ms)')
plt.ylabel('Empirical Probability')
plt.title('Empirical Probability Distribution of RTT: Kyber512')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("./plots/Kyber512_exponential_fit.png")

######### Kyber768

rtt_client = np.array(kyber768_client_rtts)
rtt_server = np.array(kyber768_server_rtts)

t_stat, p_value = ttest_ind(rtt_client, rtt_server, equal_var=False)

# Display results
print("For Kyber768")
print(f"T-statistic: {t_stat:.4f}")
print(f"P-value: {p_value:.4f}")

# Interpret
alpha = 0.05
if p_value < alpha:
    print("Result: Reject the null hypothesis (means are significantly different)")
else:
    print("Result: Accept the null hypothesis (no significant difference between means)")

# Fit exponential distribution: returns (loc, scale), where scale = 1/lambda
loc_c, scale_c = expon.fit(rtt_client, floc=0)
loc_s, scale_s = expon.fit(rtt_server, floc=0)

# x range for plotting the fitted distribution
x = np.linspace(min(rtt_client.min(), rtt_server.min()),
                max(rtt_client.max(), rtt_server.max()), 100)
# Create histogram bins
bins = np.linspace(min(rtt_client.min(), rtt_server.min()),
                   max(rtt_client.max(), rtt_server.max()), 90)

# Plot normalized histograms (PDF approximation)
plt.figure(figsize=(8, 5))
plt.hist(rtt_client, bins=bins, density=True, histtype='step', label='Client', color='blue')
plt.hist(rtt_server, bins=bins, density=True, histtype='step', label='Server', color='red')

# Plot fitted exponential PDFs
plt.plot(x, expon.pdf(x, loc=loc_c, scale=scale_c), 'b--', label=f'Client Exp Fit (λ={1/scale_c:.2f})', linewidth=0.8)
plt.plot(x, expon.pdf(x, loc=loc_s, scale=scale_s), 'r--', label=f'Server Exp Fit (λ={1/scale_s:.2f})', linewidth=0.8)


plt.xlabel('RTT (ms)')
plt.ylabel('Empirical Probability')
plt.title('Empirical Probability Distribution of RTT: Kyber768')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("./plots/Kyber768_exponential_fit.png")


####### Kyber 1024

rtt_client = np.array(kyber1024_client_rtts)
rtt_server = np.array(kyber1024_server_rtts)

t_stat, p_value = ttest_ind(rtt_client, rtt_server, equal_var=False)

# Display results
print("For Kyber1024")
print(f"T-statistic: {t_stat:.4f}")
print(f"P-value: {p_value:.4f}")

# Interpret
alpha = 0.05
if p_value < alpha:
    print("Result: Reject the null hypothesis (means are significantly different)")
else:
    print("Result: Accept the null hypothesis (no significant difference between means)")

# Fit exponential distribution: returns (loc, scale), where scale = 1/lambda
loc_c, scale_c = expon.fit(rtt_client, floc=0)
loc_s, scale_s = expon.fit(rtt_server, floc=0)

# x range for plotting the fitted distribution
x = np.linspace(min(rtt_client.min(), rtt_server.min()),
                max(rtt_client.max(), rtt_server.max()), 100)
# Create histogram bins
bins = np.linspace(min(rtt_client.min(), rtt_server.min()),
                   max(rtt_client.max(), rtt_server.max()), 90)

# Plot normalized histograms (PDF approximation)
plt.figure(figsize=(8, 5))
plt.hist(rtt_client, bins=bins, density=True, histtype='step', label='Client', color='blue')
plt.hist(rtt_server, bins=bins, density=True, histtype='step', label='Server', color='red')

# Plot fitted exponential PDFs
plt.plot(x, expon.pdf(x, loc=loc_c, scale=scale_c), 'b--', label=f'Client Exp Fit (λ={1/scale_c:.2f})', linewidth=0.8)
plt.plot(x, expon.pdf(x, loc=loc_s, scale=scale_s), 'r--', label=f'Server Exp Fit (λ={1/scale_s:.2f})', linewidth=0.8)


plt.xlabel('RTT (ms)')
plt.ylabel('Empirical Probability')
plt.title('Empirical Probability Distribution of RTT: Kyber1024')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("./plots/Kyber1024_exponential_fit.png")




###### More Plotting

security_levels = ['TLS 1.3', 'Kyber512', 'Kyber768', 'Kyber1024']
init_times = [11.8122, 18.09200, 28.28343, 43.144597]

# Convert x-axis to numerical positions for line plot
x_positions = range(len(security_levels))

# Plotting
plt.figure(figsize=(8, 5))
plt.plot(x_positions, init_times, marker='o', linestyle='-', color='blue', label='Initiation Time')
plt.xticks(x_positions, security_levels)
plt.xlabel('Security Level')
plt.ylabel('Total Session Initiation Time (ms)')
plt.title('Session Initiation Time by Security Level')
plt.grid(True)

# Annotate data points
for x, y in zip(x_positions, init_times):
    plt.text(x, y + 0.5, f"{y:.2f}", ha='center', va='bottom')

plt.tight_layout()
plt.savefig("plots/Total_Session_Initiation_Time_plot.png")

# Throughput values in MB/s
plt.clf()
client_speeds = [3.0068422, 0.8249272556, 0.7429699843, 0.5162354095]
server_speeds = [2.83748201, 0.75713224682, 0.69650332219, 0.488850969975]

# Plot lines
plt.plot(x_positions, client_speeds, 'o-b', label='Client Sending Speed')
plt.plot(x_positions, server_speeds, 'o-r', label='Server Receiving Speed')

# Labeling
plt.xticks(x_positions, security_levels)
plt.xlabel("Security Level")
plt.ylabel("Speed (MB/s)")
plt.title("Client vs Server Data Speeds")
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig("plots/total_send_receive_speed.png")

#
#
# ############ Plotting Gausian
#
# mu_client, std_client = norm.fit(kyber512_client_rtts)
# mu_server, std_server = norm.fit(kyber512_server_rtts)
#
# # Plot histograms and KDEs for reference
# plt.figure(figsize=(10, 6))
# sns.histplot(kyber512_client_rtts, bins=30, kde=True, color='blue', stat="density", alpha=0.3, label='Client RTT')
# sns.histplot(kyber512_server_rtts, bins=30, kde=True, color='red', stat="density", alpha=0.3, label='Server RTT')
#
# # Plot fitted Gaussian PDFs
# xmin = min(np.array(kyber512_client_rtts).min(), np.array(kyber512_server_rtts).min())
# xmax = max(np.array(kyber512_client_rtts).max(), np.array(kyber512_server_rtts).max())
# x = np.linspace(xmin, xmax, 200)
#
# plt.plot(x, norm.pdf(x, mu_client, std_client), 'b-', lw=2, label=f'Client Gaussian (μ={mu_client:.1f}, σ={std_client:.1f})')
# plt.plot(x, norm.pdf(x, mu_server, std_server), 'r-', lw=2, label=f'Server Gaussian (μ={mu_server:.1f}, σ={std_server:.1f})')
#
# plt.xlabel("RTT (ms)")
# plt.ylabel("Density")
# plt.title("Gaussian Fit to Client and Server RTT")
# plt.legend()
# plt.grid(True)
# plt.show()
#
#
# ############ PLotting ECDF ###############
#
# def plot_ecdf(data, label):
#     x = np.sort(data)
#     y = np.arange(1, len(x)+1) / len(x)
#     plt.step(x, y, where='post', label=label)
#
# # Example usage:
# plot_ecdf(simple_client_rtts, "TLS 1.3 client")
# plot_ecdf(simple_server_rtts, "TLS 1.3 server")
#
# plot_ecdf(kyber512_client_rtts, "Kyber512 client")
# plot_ecdf(kyber512_server_rtts," Kyber512 server")
#
# plot_ecdf(kyber768_server_rtts," Kyber768 server")
# plot_ecdf(kyber768_client_rtts, "kyber768 client")
#
# plot_ecdf(kyber1024_client_rtts, "kyber1024 client")
# plot_ecdf(kyber1024_server_rtts, "kyber1024 server")
#
# plt.xlabel("RTT (ms)")
# plt.ylabel("Empirical CDF")
# plt.legend()
# plt.show()




########### Plotting #############

# Plot Simple
title_simple = "Client vs Server RTT: TLS 1.3"
filename_simple = "rtt_simple"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in simple_client_timestamps], simple_client_rtts, label="Client RTT", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in simple_client_timestamps], simple_server_rtts, label="Server RTT", color='red')

plt.xlabel("Timestamp (s)")
plt.ylabel("RTT (ms)")
plt.title(title_simple)


# Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(simple_client_timestamps), step),
#            labels=[simple_client_timestamps[i] for i in range(0, len(simple_client_timestamps), step)],
#            rotation=45)  # rotate for better readability

plt.axvline(x=timestamp_to_seconds("57:11.0"), color='yellow', linestyle='--', linewidth=1.5, label='TLS 1.3 Handshake')
plt.axvline(x=timestamp_to_seconds("57:11.1"), color='yellow', linestyle='--', linewidth=1.5)

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
title_kyber512 = "Client vs Server RTT: Kyber512"
filename_kyber512 = "rtt_kyber512"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in kyber512_client_timestamps], kyber512_client_rtts, label="Client RTT", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in kyber512_client_timestamps], kyber512_server_rtts, label="Server RTT", color='red')

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
plt.ylabel("RTT (ms)")
plt.title(title_kyber512)
# # Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(kyber512_client_timestamps), step),
#            labels=[kyber512_client_timestamps[i] for i in range(0, len(kyber512_client_timestamps), step)],
#            rotation=45)  # rotate for better readability

plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("./plots/" + filename_kyber512 + ".png")

###################
# Plot RTT kyber768
###################
title_kyber768 = "Client vs Server RTT: Kyber768"
filename_kyber768 = "rtt_kyber768"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in kyber768_client_timestamps], kyber768_client_rtts, label="Client RTT", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in kyber768_client_timestamps], kyber768_server_rtts, label="Server RTT", color='red')

plt.xlabel("Timestamp (s)")
plt.ylabel("RTT (ms)")
plt.title(title_kyber768)
# # Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(kyber768_client_timestamps), step),
#            labels=[kyber768_client_timestamps[i] for i in range(0, len(kyber768_client_timestamps), step)],
#            rotation=45)  # rotate for better readability

plt.axvline(x=timestamp_to_seconds("19:45.1"), color='yellow', linestyle='--', linewidth=1.5, label='TLS 1.3 and Hybrid Handshake')
plt.axvline(x=timestamp_to_seconds("19:45.3"), color='yellow', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("20:40.3"), color='green', linestyle='--', linewidth=1.5, label='image 1')
plt.axvline(x=timestamp_to_seconds("20:45.3"), color='green', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("21:05.4"), color='orange', linestyle='--', linewidth=1.5, label='image 2')
plt.axvline(x=timestamp_to_seconds("21:10.1"), color='orange', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("21:25.1"), color='purple', linestyle='--', linewidth=1.5, label='image 3')
plt.axvline(x=timestamp_to_seconds("21:29.2"), color='purple', linestyle='--', linewidth=1.5)

plt.axvline(x=timestamp_to_seconds("21:59.6"), color='black', linestyle='--', linewidth=1.5, label='video')
plt.axvline(x=timestamp_to_seconds("22:30.8"), color='black', linestyle='--', linewidth=1.5)

plt.grid(True)
plt.legend()
plt.tight_layout()

plt.savefig("./plots/" + filename_kyber768 + ".png")

###################
# Plot RTT kyber1024
###################
title_kyber1024 = "Client vs Server RTT: Kyber1024"
filename_kyber1024 = "rtt_kyber1024"
plt.figure(figsize=(15, 6))

plt.plot([timestamp_to_seconds(ts) for ts in kyber1024_client_timestamps], kyber1024_client_rtts, label="Client RTT", color='blue')
plt.plot([timestamp_to_seconds(ts) for ts in kyber1024_client_timestamps], kyber1024_server_rtts, label="Server RTT", color='red')

plt.xlabel("Timestamp (s)")
plt.ylabel("RTT (ms)")
plt.title(title_kyber1024)
# Show only every 10th timestamp on x-axis
# step = 10  # adjust this value based on how readable you want it
# plt.xticks(ticks=range(0, len(kyber1024_client_timestamps), step),
#            labels=[kyber1024_client_timestamps[i] for i in range(0, len(kyber1024_client_timestamps), step)],
#            rotation=45)  # rotate for better readability
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


plt.grid(True)
plt.legend()
plt.tight_layout()

plt.savefig("./plots/" + filename_kyber1024 + ".png")