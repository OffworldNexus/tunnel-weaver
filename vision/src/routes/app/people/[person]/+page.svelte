<script lang="ts">
	import { page } from '$app/state';

	import PersonDetail from './PersonDetail.svelte';
</script>

{#key page.params.person}
	<PersonDetail id={page.params.person ?? ''} />
{/key}
