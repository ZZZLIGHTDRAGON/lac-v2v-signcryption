import unittest
from test_lac_real import TestLACOfficial
from test_lac_traceability import TestLACTraceability
from test_lac_signcrypt import TestLACSigncrypt

def create_test_suite():
    """
    车联网伪名方案完整测试套件
    基于 LAC 格密码的全流程验证
    """
    suite = unittest.TestSuite()
    
    # 1. LAC 基础算法测试
    suite.addTest(unittest.makeSuite(TestLACOfficial))
    
    # 2. TMA 伪名 + 可追溯性测试
    suite.addTest(unittest.makeSuite(TestLACTraceability))
    
    # 3. 安全通信 + 密钥协商测试
    suite.addTest(unittest.makeSuite(TestLACSigncrypt))
    
    return suite

if __name__ == '__main__':
    """
    运行全部测试：
    - LAC PKE / KEM 正确性
    - 车联网伪名生成
    - 部分密钥 K_i 加密解密
    - TMA 密钥协商
    - 消息加密传输
    - 可追溯性验证
    """
    runner = unittest.TextTestRunner(verbosity=2)
    full_suite = create_test_suite()
    runner.run(full_suite)
