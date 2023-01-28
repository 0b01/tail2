import { useEffect, useState } from 'react';
import {
  Card,
  CardHeader,
  ListItemText,
  List,
  ListItem,
  Divider,
  Switch,
  ListItemAvatar,
  Avatar,
  styled,
  Grid,
  Button,
  CardContent,
  ListItemButton,
  Modal,
  Typography,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  Slider,
  TextField,
  Link
} from '@mui/material';
import LockTwoToneIcon from '@mui/icons-material/LockTwoTone';
import PhoneLockedTwoToneIcon from '@mui/icons-material/PhoneLockedTwoTone';
import EmailTwoToneIcon from '@mui/icons-material/EmailTwoTone';
import Text from 'src/components/Text';
import { AddTwoTone, CheckTwoTone, PauseTwoTone, PlayArrow, PlayArrowTwoTone, SmartToyTwoTone, StopTwoTone } from '@mui/icons-material';
import { Box } from '@mui/system';
import { IAgentProps, INewProbeModalProps, start_probe, stop_probe } from './types';
import { NewProbeModal } from './NewProbeModal';

const AvatarWrapperError = styled(Avatar)(
  ({ theme }) => `
      background-color: ${theme.colors.error.lighter};
      color:  ${theme.colors.error.main};
`
);

const AvatarWrapperSuccess = styled(Avatar)(
  ({ theme }) => `
      background-color: ${theme.colors.success.lighter};
      color:  ${theme.colors.success.main};
`
);

const AvatarWrapperWarning = styled(Avatar)(
  ({ theme }) => `
      background-color: ${theme.colors.warning.lighter};
      color:  ${theme.colors.warning.main};
`
);

function AgentCard(props: IAgentProps) {
  const [agent, setAgent] = useState(props.agent);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setAgent(props.agent);
  }, [props.agent]);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  
  let add_probe = <ListItemButton onClick={handleOpen}>
    <ListItemAvatar>
      <AvatarWrapperSuccess>
        <AddTwoTone />
      </AvatarWrapperSuccess>
    </ListItemAvatar>
    <ListItemText
      primary={<Text color="black">New Probe</Text>}
      primaryTypographyProps={{
        gutterBottom: true,
        noWrap: true
      }}
    />
  </ListItemButton>

  let modal = <NewProbeModal open={open} handleClose={handleClose} name={props.host_name} />;
  let probes = agent.probes.map((nfo) => {
    let txt;
    let scope;
    switch(nfo[0].scope.type) {
      case "Pid":
        scope = `Pid(${nfo[0].scope.pid})`;
        break;
      case "SystemWide":
        scope = `*`;
    };
    switch (nfo[0].type) {
      case 'Perf':
        txt = `${nfo[0].type}(${nfo[0].period}) @ ${scope}`;
        break;
      case 'Uprobe':
        txt = `${nfo[0].type}(${nfo[0].uprobe}) @ ${scope}`;
        break;
    };

    var baseURL = window.document.URL;
    const data_url = new URL("/api/current", baseURL);
    data_url.search = new URLSearchParams({host_name: props.host_name, probe: JSON.stringify(nfo[0])}).toString();
    const flamegraph_url = new URL("/flamegraph/app.html", baseURL);
    flamegraph_url.searchParams.append("profileURL", data_url.toString());

          return <ListItem
            key={JSON.stringify(nfo[0])}
            sx={{
              py: 2
            }}
          >
            {/* <ListItemAvatar>
              <AvatarWrapperSuccess>
                <PhoneLockedTwoToneIcon />
              </AvatarWrapperSuccess>
            </ListItemAvatar> */}
            <ListItemText
              primary={<Link color="black" onClick={() => window.open(flamegraph_url)}>{txt}</Link>}
              primaryTypographyProps={{
                variant: 'body1',
                fontWeight: 'bold',
                color: 'textPrimary',
                gutterBottom: true,
                noWrap: true
              }}
              secondary={nfo[1].is_running ? <Text color="success">Active</Text> : <Text color="black">Stopped</Text>}
              secondaryTypographyProps={{ variant: 'body2', noWrap: true }}
            />
            <Switch
              edge="end"
              color="primary"
              onChange={(e) => e.target.checked ? start_probe(props.host_name, nfo[0]) : stop_probe(props.host_name, nfo[0])}
              checked={nfo[1].is_running}
            />
          </ListItem>
  });

  let stop_agent = async () => {
    await fetch(`/api/agent/halt?name=${props.host_name}`);
  }

  return (
    <Grid item md={3}>
      {modal}
      <Card style={{marginBottom: '10px', minWidth: "275px"}}>
        <CardHeader
          avatar={
            agent.is_halted ? 
              <AvatarWrapperError>
                <SmartToyTwoTone />
              </AvatarWrapperError>
            :
              <AvatarWrapperSuccess>
                <SmartToyTwoTone />
              </AvatarWrapperSuccess>
          }
          action={agent.is_halted? null : <Button color="error" onClick={() => stop_agent()}>Stop</Button>}
          title={props.host_name}
          titleTypographyProps={{
            variant: 'body1',
            fontWeight: 'bold',
            color: 'textPrimary',
            gutterBottom: true,
            noWrap: true
          }}
        />
        <Divider />
        <List disablePadding>
          {probes}
          <Divider />
          {add_probe}
          {/* <ListItem
            sx={{
              py: 2
            }}
          >
            <ListItemAvatar>
              <AvatarWrapperSuccess>
                <PhoneLockedTwoToneIcon />
              </AvatarWrapperSuccess>
            </ListItemAvatar>
            <ListItemText
              primary={<Text color="black">Phone Verification</Text>}
              primaryTypographyProps={{
                variant: 'body1',
                fontWeight: 'bold',
                color: 'textPrimary',
                gutterBottom: true,
                noWrap: true
              }}
              secondary={<Text color="success">Active</Text>}
              secondaryTypographyProps={{ variant: 'body2', noWrap: true }}
            />
            <Switch
              edge="end"
              color="primary"
              onChange={handleToggle('phone_verification')}
              checked={checked.indexOf('phone_verification') !== -1}
            />
          </ListItem>
          <Divider />
          <ListItem
            sx={{
              py: 2
            }}
          >
            <ListItemAvatar>
              <AvatarWrapperWarning>
                <EmailTwoToneIcon />
              </AvatarWrapperWarning>
            </ListItemAvatar>
            <ListItemText
              primary={<Text color="black">Recovery Email</Text>}
              primaryTypographyProps={{
                variant: 'body1',
                fontWeight: 'bold',
                color: 'textPrimary',
                gutterBottom: true,
                noWrap: true
              }}
              secondary={<Text color="warning">Not completed</Text>}
              secondaryTypographyProps={{ variant: 'body2', noWrap: true }}
            />
            <Switch
              edge="end"
              color="primary"
              onChange={handleToggle('recovery_email')}
              checked={checked.indexOf('recovery_email') !== -1}
            />
          </ListItem> */}
        </List>
      </Card>
    </Grid>
  );
}

export default AgentCard;
