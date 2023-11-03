# encryptIOn

`netcat` is a simple and super cool program. You just specify a listening port, then connect to it, then write some stuff over the network. It feels like magic ✨

But what would you say if I told you that you can have an *encrypted* version of netcat that uses hardware-assisted encryption, and can run on virtual machines?

> Hardware-assisted encryption on virtual machines? But that's slow 🐌

First of all, let me finish. Second, I've also made a non-virtualized version just for you. Third and most important, encryptIOn is *paravirtualized*. That means it **knows** that it's running inside a virtual machine:

![](assets/matrix.gif)

This way, the system calls that use hardware-assisted encryption can be offloaded to the actual hardware, and not everything has to be virtualized. So it's still super fast 🔥

This is made possible by a custom virtIO driver for the chat.

What do you have to say now?

> Nothing. I'm sorry I ever doubted you.

That's more like it. Happy chatting!
