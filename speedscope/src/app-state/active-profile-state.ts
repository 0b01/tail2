import {Profile} from '../lib/profile'
import {getProfileToView} from './getters'
import {flattenRecursionAtom, profileGroupAtom} from '.'
import {FlamechartViewState, SandwichViewState} from './profile-group'
import {useAtom} from '../lib/atom'

export interface ApplicationState {}

export interface ActiveProfileState {
  profile: Profile
  chronoViewState: FlamechartViewState
  leftHeavyViewState: FlamechartViewState
  sandwichViewState: SandwichViewState
}

export function useActiveProfileState(): ActiveProfileState | null {
  const flattenRecursion = useAtom(flattenRecursionAtom)
  const profileGroupState = useAtom(profileGroupAtom)

  if (!profileGroupState) return null
  const profileState = profileGroupState.profile;
  return {
    ...profileGroupState.profile,
    profile: getProfileToView({
      profile: profileState.profile,
      flattenRecursion,
    }),
  }
}
