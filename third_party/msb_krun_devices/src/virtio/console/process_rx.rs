use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use vm_memory::{GuestMemoryBackend, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::PortInput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    input: Arc<Mutex<Box<dyn PortInput + Send>>>,
    control: Arc<ConsoleControl>,
    port_id: u32,
    stopfd: utils::eventfd::EventFd,
    stop: Arc<AtomicBool>,
) {
    let mem = &mem;
    let mut eof = false;

    let mut input = input.lock().unwrap();
    loop {
        let head = pop_head_blocking(&mut queue, mem, &interrupt);

        let head_index = head.index;
        let mut bytes_read = 0;
        for chain in head.into_iter().writable() {
            match read_to_desc(chain, input.as_mut(), &mut eof) {
                Ok(0) => {
                    break;
                }
                Ok(len) => {
                    bytes_read += len;
                }
                Err(e) => {
                    log::error!("Failed to read: {e:?}")
                }
            }
        }

        if bytes_read != 0 {
            log::trace!("Rx {bytes_read} bytes queue len{}", queue.len(mem));
            if let Err(e) = queue.add_used(mem, head_index, bytes_read as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        // We signal_used_queue only when we get WouldBlock or EOF
        if eof {
            interrupt.signal_used_queue();
            log::trace!("signaling EOF on port {port_id}");
            control.port_open(port_id, false);
            return;
        } else if bytes_read == 0 {
            queue.undo_pop();
            interrupt.signal_used_queue();
            input.wait_until_readable(Some(&stopfd));
        }

        if stop.load(Ordering::Acquire) {
            return;
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    interrupt: &InterruptTransport,
) -> DescriptorChain<'mem> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break descriptor,
            None => {
                interrupt.signal_used_queue();
                thread::park();
                log::trace!("rx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

#[allow(deprecated)]
fn read_to_desc(
    desc: DescriptorChain,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let mut target = region.get_slice(addr, len).unwrap();
            match input.read_volatile(&mut target) {
                Ok(n) => {
                    if n == 0 {
                        *eof = true
                    }
                    Ok(n)
                }
                // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(GuestMemoryError::IOError(e)),
            }
        })
}
