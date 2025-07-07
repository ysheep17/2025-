from blind_watermark import WaterMark
import cv2
import numpy as np
import os
import math
import traceback
from PIL import Image

class WatermarkProcessor:
    def __init__(self, password=1234):
        self.password = password
        # 添加中文路径支持
        # 禁用多进程以避免中文路径问题
        self.bwm = WaterMark(password_img=1, password_wm=1, processes=1)
        self.attack_methods = {
            'flip': self.flip_attack,
            'translate': self.translate_attack,
            'crop': self.crop_attack,
            'contrast': self.contrast_attack
        }

    def embed_watermark(self, img_path, watermark_path, output_img):
        """嵌入水印到原始图像"""
        # 验证图像文件是否存在
        if not os.path.exists(img_path):
            raise FileNotFoundError(f"原始图像文件不存在: {img_path}")
        
        # 验证水印文件是否存在
        if not os.path.exists(watermark_path):
            raise FileNotFoundError(f"水印文件不存在: {watermark_path}")
        
        # 读取水印文本内容（关键修复）
        with open(watermark_path, 'r', encoding='utf-8') as f:
            watermark_text = f.read().strip()
            if not watermark_text:
                raise ValueError("水印文本不能为空")
        
        self.bwm.read_img(img_path)
        self.bwm.read_wm(watermark_text, mode='str')
        self.bwm.embed(output_img)
        
        # 使用官方推荐方式获取水印长度
        wm_shape = len(self.bwm.wm_bit)
        return output_img, wm_shape

    def extract_watermark(self, img_path, wm_shape, output_wm_path):
        """从图像中提取水印"""
        if not os.path.exists(img_path):
            raise FileNotFoundError(f"待提取图像文件不存在: {img_path}")
        
        # 修改：提取文本水印时不使用out_wm_name参数，而是捕获返回值
        # 确保wm_shape是整数而非元组
        if isinstance(wm_shape, tuple):
            wm_shape = wm_shape[0]  # 从(25, 1)提取25
        wm_extract = self.bwm.extract(img_path, wm_shape=wm_shape, mode='str')
        # 手动将文本水印写入文件
        with open(output_wm_path, 'w', encoding='utf-8') as f:
            f.write(wm_extract)
        print(f"水印已提取: {output_wm_path}")
        return output_wm_path

    # 攻击方法实现
    def flip_attack(self, img):
        """水平翻转攻击"""
        return cv2.flip(img, 1)

    def translate_attack(self, img):
        """平移攻击"""
        rows, cols = img.shape[:2]
        M = np.float32([[1,0,50],[0,1,30]])  # 向右平移50，向下平移30
        return cv2.warpAffine(img, M, (cols, rows))

    def crop_attack(self, img):
        """裁剪攻击 - 保留中心区域"""
        rows, cols = img.shape[:2]
        # 确保裁剪后的图像不会太小
        crop_size = min(rows, cols) // 2
        start_row = max(0, rows//2 - crop_size//2)
        start_col = max(0, cols//2 - crop_size//2)
        return img[start_row:start_row+crop_size, start_col:start_col+crop_size]

    def contrast_attack(self, img):
        """对比度调整攻击"""
        return cv2.convertScaleAbs(img, alpha=1.2, beta=20)  # 适度调整对比度

    def run_robustness_test(self, watermarked_img_path, wm_shape, img_name):
        """执行所有鲁棒性测试"""
        img = cv2.imread(watermarked_img_path)
        if img is None:
            raise FileNotFoundError(f"无法读取图像文件: {watermarked_img_path}")

        # 创建输出目录（按图片名称区分）
        output_dir = os.path.join('attack_results', img_name)
        os.makedirs(output_dir, exist_ok=True)

        # 对每种攻击类型执行测试
        for attack_name, attack_func in self.attack_methods.items():
            try:
                # 应用攻击
                attacked_img = attack_func(img)
                attacked_img_path = os.path.join(output_dir, f'attacked_{attack_name}.png')
                cv2.imwrite(attacked_img_path, attacked_img)

                # 提取水印
                extracted_wm_path = os.path.join(output_dir, f'extracted_{attack_name}_wm.txt')
                self.extract_watermark(attacked_img_path, wm_shape, extracted_wm_path)
            except Exception as e:
                print(f"{attack_name}攻击处理失败: {str(e)}")

        print(f"图片 {img_name} 的鲁棒性测试已完成，结果保存在: {output_dir}")

if __name__ == '__main__':
    # 配置参数 - 使用绝对路径确保兼容性
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    PICS_DIR = os.path.join(CURRENT_DIR, 'pics')
    WATERMARK_TEXT_PATH = os.path.join(CURRENT_DIR, 'watermark.txt')
    OUTPUT_DIR = os.path.join(CURRENT_DIR, 'watermarked_images')

    # 创建默认水印文件（如果不存在）
    if not os.path.exists(WATERMARK_TEXT_PATH):
        with open(WATERMARK_TEXT_PATH, 'w', encoding='utf-8') as f:
            f.write('This is a test watermark.')
        print(f"已创建默认水印文件: {WATERMARK_TEXT_PATH}")

    # 获取pics目录下的所有图片文件
    image_extensions = ('.jpg', '.jpeg', '.png', '.bmp')
    image_paths = []
    if os.path.exists(PICS_DIR):
        image_paths = [
            os.path.join(PICS_DIR, f) 
            for f in os.listdir(PICS_DIR) 
            if f.lower().endswith(image_extensions)
        ]
    
    if not image_paths:
        print(f"在 {PICS_DIR} 目录下未找到任何图片文件")
        exit(1)

    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 创建处理器实例
    processor = WatermarkProcessor(password=1234)

    try:
        # 批量处理所有图片
        for img_path in image_paths:
            # 获取图片名称（不含扩展名）
            img_name = os.path.splitext(os.path.basename(img_path))[0]
            print(f"\n处理图片: {img_name}")

            # 嵌入水印 - 获取实际水印形状
            output_img = os.path.join(OUTPUT_DIR, f'{img_name}_watermarked.png')
            output_img, wm_shape = processor.embed_watermark(img_path, WATERMARK_TEXT_PATH, output_img)
            print(f"实际使用的水印形状: {wm_shape}")

            # 提取原始水印
            processor.extract_watermark(output_img, wm_shape, os.path.join(OUTPUT_DIR, f'{img_name}_extracted_original_wm.txt'))

            # 执行鲁棒性测试
            processor.run_robustness_test(output_img, wm_shape, img_name)

        print(f"\n所有图片处理完成！")
        print(f"水印图像保存在: {OUTPUT_DIR}")
        print(f"攻击测试结果保存在: {os.path.join(CURRENT_DIR, 'attack_results')}")

    except Exception as e:
        # 修复print语句错误
        print(f"处理过程中出错: {str(e)}")
        traceback.print_exc()
    # 添加路径调试信息
    print(f"工作目录: {os.getcwd()}")
    print(f"水印文件路径: {WATERMARK_TEXT_PATH}, 存在: {os.path.exists(WATERMARK_TEXT_PATH)}")
