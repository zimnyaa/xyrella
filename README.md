# xyrella

`xyrella` is a simple XLL builder without any remote injection functionality (it can unhook NTDLL, though). I sincerely believe that it makes things easier when you separate your intial access method and your injection/EDR bypass technique.

The approach is briefly discussed in https://tishina.in/initial-access/xll-delivery


From the execution standpoint, `xyrella` is just [nim-fibers](https://tishina.in/execution/nim-fibers), compiled to a DLL. The usage is pretty straightforward:
![image](https://user-images.githubusercontent.com/502153/152382743-c792991f-331e-4b2d-9f20-b12d66650049.png)
