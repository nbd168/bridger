#ifndef __BRIDGER_BPF_H
#define __BRIDGER_BPF_H

int bridger_bpf_init(void);
int bridger_bpf_device_attach(struct device *dev);
void bridger_bpf_device_detach(struct device *dev);
void bridger_bpf_flow_upload(struct bridger_flow *flow);
void bridger_bpf_flow_update(struct bridger_flow *flow);
void bridger_bpf_flow_delete(struct bridger_flow *flow);

#endif
