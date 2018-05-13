# Triton Emulator

基于Triton实现的x86下的Linux程序模拟器

### 依赖

`Triton`   `pwntools`   `peda`

### 模块

**emulator.py**: 基本类库，完成程序初始化功能

**syscall.py**: 基本类库，模拟系统调用

**debugger.py**：继承自emulator.py，一个简易调试器

**solve.py**：一个基于符号执行求解的样例

