# import matplotlib.pyplot as plt
# import numpy as np

# def plot_cwnd_data(file_path='cwnd.txt', output_image='cwnd_plot.png'):
#     """
#     从文件中读取拥塞窗口数据并绘制图表。

#     Args:
#         file_path (str): 包含cwnd数据的文本文件路径。
#         output_image (str): 输出图像的文件名。
#     """
#     try:
#         # 使用numpy.loadtxt直接读取数据，跳过注释并解包到不同数组
#         time_data, cwnd_data, ssthresh_data = np.loadtxt(
#             file_path, 
#             comments='//', 
#             usecols=(0, 1, 2),
#             unpack=True
#         )

#         # 使用向量化操作进行数据转换
#         cwnd_data /= 1460  # 转换为以MSS为单位
#         ssthresh_data /= 1460  # 转换为以MSS为单位
#         time_data /= 1_000_000  # 转换为秒

#         # 绘图
#         plt.figure(figsize=(12, 6))
#         plt.plot(time_data, cwnd_data, 'b-', linewidth=2, label='cwnd')
#         plt.plot(time_data, ssthresh_data, 'r--', linewidth=1.5, label='ssthresh')
        
#         plt.xlabel('Time (s)')
#         plt.ylabel('Window Size (MSS)')
#         plt.title('Congestion Window (cwnd) and Slow Start Threshold (ssthresh) Over Time')
#         plt.grid(True, alpha=0.3)
#         plt.legend()

#         plt.savefig(output_image, dpi=300)
#         plt.show()

#     except FileNotFoundError:
#         print(f"错误: 未找到数据文件 '{file_path}'。")
#     except ValueError:
#         print(f"错误: 解析 '{file_path}' 文件失败，请检查文件格式是否正确。")
#     except Exception as e:
#         print(f"发生未知错误: {e}")

# if __name__ == '__main__':
#     plot_cwnd_data()

import matplotlib.pyplot as plt
import numpy as np

time_data = []
cwnd_data = []
ssthresh_data = []

with open('cwnd.txt', 'r') as file:
    for line in file:
        if line.startswith('//'):
            continue
        
        values = line.strip().split()
        if len(values) >= 3:
            time_data.append(float(values[0]))
            cwnd_data.append(float(values[1]))
            ssthresh_data.append(float(values[2]))

cwnd_data = [data / 1460 for data in cwnd_data]
ssthresh_data = [data / 1460 for data in ssthresh_data]
time_data = [float(data) / 1000000 for data in time_data]
plt.figure(figsize=(12, 6))
plt.plot(time_data, cwnd_data, 'b-', linewidth=2, label='cwnd')
plt.plot(time_data, ssthresh_data, 'r--', linewidth=1.5, label='ssthresh')
plt.xlabel('times (s)')
plt.ylabel('(MSS)')
plt.title('change')
plt.grid(True, alpha=0.3)
plt.legend()


plt.savefig('cwnd_plot.png', dpi=300)
plt.show()