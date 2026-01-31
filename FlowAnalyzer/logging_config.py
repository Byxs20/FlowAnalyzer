import logging


def configure_logger(logger_name, level=logging.DEBUG) -> logging.Logger:
    # 创建一个 logger 对象
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)

    # 创建一个处理器，将日志输出到控制台
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)

    # 创建一个格式化器，定义日志的输出格式
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    return logger


logger = configure_logger("FlowAnalyzer", logging.INFO)

if __name__ == "__main__":
    logger = configure_logger("FlowAnalyzer")
    logger.info("This is a test!")
