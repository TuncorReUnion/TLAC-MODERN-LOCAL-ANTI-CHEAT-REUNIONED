use aya::{Bpf, programs::TracePoint};

pub fn load_ebpf() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpf = Bpf::load_file("bpf/program.bpf.o")?;
    let program: &mut TracePoint = bpf.program_mut("trace_openat")?.try_into()?;
    program.load()?;
    program.attach()?;
    println!("✅ eBPF programı yüklendi!");
    Ok(())
}
