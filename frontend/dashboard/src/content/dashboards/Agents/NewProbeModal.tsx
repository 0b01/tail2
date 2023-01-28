import { Box, Button, Card, FormControl, FormGroup, InputLabel, MenuItem, Modal, Select, TextField, Typography } from "@mui/material";
import { useState } from "react";
import { INewProbeModalProps, IScope, make_perf_probe, make_uprobe_probe, ProbeTypes, start_probe } from "./types";


export function NewProbeModal(props: INewProbeModalProps) {
  let [mode, setMode] = useState<ProbeTypes>("Perf");
  let [uprobe, setUprobe] = useState("libc:malloc");
  let [period, setPeriod] = useState(400000);
  let [scope, setScope] = useState<IScope>({type: "SystemWide", pid: 0} as any);

  let args;
  if (mode == "Perf")
  {
    args = <TextField label="Period" inputProps={{ inputMode: 'numeric', pattern: '[0-9]*' }} value={period} onChange={(e) => setPeriod(parseInt(e.target.value))} />
  } else if (mode == "Uprobe")
  {
    args = <TextField label="uprobe" inputProps={{ pattern: '.+:.+' }} value={uprobe} onChange={(e) => setUprobe(e.target.value)} />
  }

  let pid = 
        <TextField label="PID" inputProps={{ inputMode: 'numeric', pattern: '[0-9]*' }} value={(scope as any).pid}
        onChange={(e) => setScope({...scope, pid: parseInt(e.target.value)} as any)} />
    ;

  return <Modal
      open={props.open}
      onClose={props.handleClose}
      aria-labelledby="modal-modal-title"
      aria-describedby="modal-modal-description"
    >
      <Card sx={modalStyle}>
        <Box p={3}>
            <Box pb={3}>
                <Typography id="modal-modal-title" variant="h5">
                    Create a new probe
                </Typography>
            </Box>
            <FormControl style={{width: '400px'}}>
                <InputLabel id="mode-label">Mode</InputLabel>
                <Select
                    key="mode"
                    labelId="mode-label"
                    id="mode"
                    value={mode}
                    label="Mode"
                    onChange={(e) => setMode(e.target.value as ProbeTypes)}
                >
                    <MenuItem value="Perf">Perf</MenuItem>
                    <MenuItem value="Uprobe">UProbe</MenuItem>
                </Select>

                {args}

            </FormControl>
            <FormControl style={{width: '400px'}}>
                <InputLabel id="scope-label">Scope</InputLabel>
                <Select
                    labelId="scope-label"
                    key="scope"
                    id="scope"
                    value={scope.type}
                    label="Scope"
                    onChange={(e) => setScope({type: e.target.value as any})}
                >
                    <MenuItem value="SystemWide">SystemWide</MenuItem>
                    <MenuItem value="Pid">Pid</MenuItem>
                </Select>

                { scope.type === "SystemWide" ? null : pid }
            </FormControl>

          <Button
            variant="contained"
            onClick={() => {
                let probe;
                if (mode == "Perf") {
                    probe = make_perf_probe(scope, period);
                } else if (mode == "Uprobe") {
                    probe = make_uprobe_probe(scope, uprobe);
                }
                start_probe(props.name, probe);
                props.handleClose();
            }}
          >
            Apply
          </Button>
        </Box>
      </Card>
    </Modal>;
}

const modalStyle = {
  position: 'absolute' as 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: 800,
  bgcolor: 'background.paper',
  border: '1px solid #ddd',
  boxShadow: 24,
  p: 4,
};
