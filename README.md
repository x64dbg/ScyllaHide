# ScyllaHideCE
This is an effort to integrate ScyllaHide, an advanced anti-anti-debugging and anti-reverse engineering tool, into Cheat Engine, a popular memory scanning and debugging software. While Cheat Engine offers robust features for stealthy debugging, it encounters difficulties when initiating the debugging of a process right from its entry point, particularly if the target game employs protection mechanisms. For instance, should one wish to investigate the unpacking routine of an obscure file format within a safeguarded game, Cheat Engine alone would not suffice for such a task with ease.

ScyllaHideCE emerges as particularly beneficial when utilizing the Windows debugger integrated within Cheat Engine.

The plugin and target bitness must match for the plugin to work flawlessly. The Options window will not inject anything (as it does in other instances) to avoid bugs in CE.

Usage Instructions:
- Incorporate the plugin into Cheat Engine’s settings.
- Navigate to the “Memory View” window and proceed to the “Plugins” tab.
- Adjust the “ScyllaHideCE mode” setting to “Attach” if you intend to attach it to an already running process, or to “Open” if you aim to commence the debugging of a new process.
- To initiate a process within Cheat Engine, firstly ensure the Windows debugger is selected within the settings.
- Subsequently, click on the “Open Process” button, choose “File”, and then select “Create Process”.

Note: If you are using VEH debugger module, disable KiUserExceptionDispatcher option. 

# ScyllaHide

ScyllaHide is an advanced open-source x64/x86 user mode Anti-Anti-Debug library. It hooks various functions to hide debugging. This tool is intended to stay in user mode (ring 3). If you need kernel mode (ring 0) Anti-Anti-Debug, please see [TitanHide](https://github.com/mrexodia/titanhide). Forked from [NtQuery/ScyllaHide](https://bitbucket.org/NtQuery/scyllahide).

ScyllaHide supports various debuggers through plugins:

- OllyDbg [v1](http://www.ollydbg.de) and [v2](http://www.ollydbg.de/version2.html)
- [x64dbg](https://x64dbg.com)
- [Hex-Rays IDA](https://www.hex-rays.com/products/ida/) v6 (not supported)
- TitanEngine v2 ([original](http://www.reversinglabs.com/open-source/titanengine.html) and [updated](https://github.com/x64dbg/TitanEngine/) versions)

PE x64 debugging is fully supported with plugins for x64dbg and IDA.

Please note that ScyllaHide is not limited to these debuggers. You can use the standalone command line version of ScyllaHide. You can inject ScyllaHide into any process debugged by any debugger.

More information is available in the [documentation](https://github.com/x64dbg/ScyllaHide/releases/download/docs-2019-05-17/ScyllaHide.pdf) (PDF).

## License
ScyllaHide is licensed under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Special thanks to
- What for his [POISON Assembler source code](https://tuts4you.com/download.php?view.2281)
- waliedassar for his [blog posts](http://waleedassar.blogspot.de)
- Peter Ferrie for his [PDFs](http://pferrie.host22.com)
- MaRKuS-DJM for [Olly Advanced](http://www.openrce.org/downloads/details/241/Olly_Advanced)
- Lim Bio Liong for [MS Spy++ style Window Finder](http://www.codeproject.com/Articles/1698/MS-Spy-style-Window-Finder)
