<script lang="ts">
	/** Param pages remount their body when the id changes (see `$app/state`). */
	import { page } from '$app/state';

	import MachineDetail from './MachineDetail.svelte';
</script>

{#key page.params.machine}
	<MachineDetail id={page.params.machine ?? ''} />
{/key}
