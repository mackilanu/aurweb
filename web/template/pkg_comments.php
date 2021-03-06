<?php
if ($comment_section == "package") {
	if (!isset($count)) {
		$count = pkgbase_comments_count($base_id, $include_deleted);
	}
}
?>


<?php if ($comment_section == "package"): ?>
<div class="comments package-comments">
<?php else: ?>
<div class="comments">
<?php endif; ?>
	<div class="comments-header">
		<h3>
			<?php if ($comment_section == "package"): ?>
				<?php if (!isset($comments)): ?>
					<?php $comments = $pinned ?>
					<span class="text"><?= __('Pinned Comments') ?></span>
					<span class="arrow"></span>
				<?php else: ?>
					<span class="text"><?= __('Latest Comments') ?></span>
					<span class="arrow"></span>
				<?php endif; ?>
			<?php elseif ($comment_section == "account"): ?>
				<?= __("Comments for") ?> <a href="<?= htmlentities(get_uri('/account/' . $username), ENT_QUOTES) ?>"><?= $username ?></a>
			<?php endif; ?>
		</h3>

		<?php if (isset($pagination_templs) && count($pagination_templs) > 1): ?>
			<p class="comments-header-nav">
				<?php foreach ($pagination_templs as $pagenr => $pagestart): ?>
					<?php if ($pagestart === false): ?>
						<span class="page"><?= $pagenr ?></span>
					<?php elseif ($pagestart === $offset): ?>
						<span class="page"><?= $pagenr ?></span>
					<?php else: ?>
						<?php if ($comment_section == "package"): ?>
							<a class="page" href="<?= htmlentities(get_pkgbase_uri($pkgbase_name), ENT_QUOTES) . '?' . mkurl('O=' . $pagestart) ?>"><?= $pagenr ?></a>
						<?php else: ?>
							<a class="page" href="<?= get_uri('/account/' . $username . '/comments/') . '?' . mkurl('O=' . $pagestart) ?>"><?= $pagenr ?></a>
						<?php endif; ?>
					<?php endif; ?>
				<?php endforeach; ?>
			</p>
		<?php endif; ?>
	</div>

	<?php foreach ($comments as $indx => $row): ?>
		<?php
		if ($comment_section == "account") {
			$pkgbase_name = $row["PackageBaseName"];
		}

		$anchor = (isset($pinned) ? "pinned-" : "comment-") . $row['ID'];
		$date_fmtd = date('Y-m-d H:i', $row['CommentTS']);
		$date_link = '<a href="#' . $anchor . '" class="date">' . $date_fmtd . '</a>';
		if ($comment_section == "package") {
			if ($row['UserName']) {
				$user_fmtd = html_format_username($row['UserName']);
				$heading = __('%s commented on %s', $user_fmtd, $date_link);
			} else {
				$heading = __('Anonymous comment on %s', $date_link);
			}
		} elseif ($comment_section == "account") {
			$pkg_uri = '<a href=' . htmlspecialchars(get_pkg_uri($row['PackageBaseName']), ENT_QUOTES) . '>' . htmlspecialchars($row['PackageBaseName']) . '</a></td>';
			$heading = __('Commented on package %s on %s', $pkg_uri, $date_link);
		}

		$is_deleted = $row['DelTS'];
		$is_edited = $row['EditedTS'];
		$is_pinned = $row['PinnedTS'];

		if ($uid && $is_deleted) {
			$date_fmtd = date('Y-m-d H:i', $row['DelTS']);
			$heading .= ' <span class="edited">(';
			if ($row['DelUserName']) {
				$user_fmtd = html_format_username($row['DelUserName']);
				$heading .= __('deleted on %s by %s', $date_fmtd, $user_fmtd);
			} else {
				$heading .= __('deleted on %s', $date_fmtd);
			}
			$heading .= ')</span>';
		} elseif ($uid && $is_edited) {
			$date_fmtd = date('Y-m-d H:i', $row['EditedTS']);
			$heading .= ' <span class="edited">(';
			if ($row['EditUserName']) {
				$user_fmtd = html_format_username($row['EditUserName']);
				$heading .= __('edited on %s by %s', $date_fmtd, $user_fmtd);
			} else {
				$heading .= __('edited on %s', $date_fmtd);
			}
			$heading .= ')</span>';
		}

		$comment_classes = "comment-header";
		if ($is_deleted) {
			$comment_classes .= " comment-deleted";
		}
		?>
		<h4 id="<?= $anchor ?>" class="<?= $comment_classes ?>">
			<?= $heading ?>
			<?php if ($is_deleted && has_credential(CRED_COMMENT_UNDELETE)): ?>
				<form class="undelete-comment-form" method="post" action="<?= htmlspecialchars(get_pkgbase_uri($pkgbase_name), ENT_QUOTES); ?>">
					<fieldset style="display:inline;">
						<input type="hidden" name="action" value="do_UndeleteComment" />
						<input type="hidden" name="comment_id" value="<?= $row['ID'] ?>" />
						<input type="hidden" name="token" value="<?= htmlspecialchars($_COOKIE['AURSID']) ?>" />
						<input type="hidden" name="return_to" value="<?= htmlspecialchars($_SERVER["REQUEST_URI"], ENT_QUOTES) ?>" />
						<input type="image" class="undelete-comment" src="/images/action-undo.min.svg" width="11" height="11" alt="<?= __('Undelete comment') ?>" title="<?= __('Undelete comment') ?>" name="submit" value="1" />
					</fieldset>
				</form>
			<?php endif;?>

			<?php if (!$is_deleted && can_delete_comment_array($row)): ?>
				<form class="delete-comment-form" method="post" action="<?= htmlspecialchars(get_pkgbase_uri($pkgbase_name), ENT_QUOTES); ?>">
					<fieldset style="display:inline;">
						<input type="hidden" name="action" value="do_DeleteComment" />
						<input type="hidden" name="comment_id" value="<?= $row['ID'] ?>" />
						<input type="hidden" name="token" value="<?= htmlspecialchars($_COOKIE['AURSID']) ?>" />
						<input type="hidden" name="return_to" value="<?= htmlspecialchars($_SERVER["REQUEST_URI"], ENT_QUOTES) ?>" />
						<input type="image" class="delete-comment" src="/images/x.min.svg" width="11" height="11" alt="<?= __('Delete comment') ?>" title="<?= __('Delete comment') ?>" name="submit" value="1" />
					</fieldset>
				</form>
			<?php endif; ?>

			<?php if (!$is_deleted && can_edit_comment_array($row)): ?>
			<a href="<?= htmlspecialchars(get_pkgbase_uri($pkgbase_name) . 'edit-comment/?comment_id=' . $row['ID'], ENT_QUOTES) ?>" class="edit-comment" title="<?= __('Edit comment') ?>"><img src="/images/pencil.min.svg" alt="<?= __('Edit comment') ?>" width="11" height="11"></a>
			<?php endif; ?>

			<?php if (!$is_deleted && !$is_pinned && can_pin_comment_array($row) && !(pkgbase_comments_count($row["PackageBaseID"], false, true) >= 5)): ?>
				<form class="pin-comment-form" method="post" action="<?= htmlspecialchars(get_pkgbase_uri($pkgbase_name), ENT_QUOTES); ?>">
					<fieldset style="display:inline;">
						<input type="hidden" name="action" value="do_PinComment" />
						<input type="hidden" name="comment_id" value="<?= $row['ID'] ?>" />
						<input type="hidden" name="package_base" value="<?= $row["PackageBaseID"] ?>" />
						<input type="hidden" name="token" value="<?= htmlspecialchars($_COOKIE['AURSID']) ?>" />
						<input type="hidden" name="return_to" value="<?= htmlspecialchars($_SERVER["REQUEST_URI"], ENT_QUOTES) ?>" />
						<input type="image" class="pin-comment" src="/images/pin.min.svg" width="11" height="11" alt="<?= __('Pin comment') ?>" title="<?= __('Pin comment') ?>" name="submit" value="1" />
					</fieldset>
				</form>
			<?php endif; ?>

			<?php if (!$is_deleted && $is_pinned && can_pin_comment_array($row)): ?>
				<form class="pin-comment-form" method="post" action="<?= htmlspecialchars(get_pkgbase_uri($pkgbase_name), ENT_QUOTES); ?>">
					<fieldset style="display:inline;">
						<input type="hidden" name="action" value="do_UnpinComment" />
						<input type="hidden" name="comment_id" value="<?= $row['ID'] ?>" />
						<input type="hidden" name="token" value="<?= htmlspecialchars($_COOKIE['AURSID']) ?>" />
						<input type="hidden" name="return_to" value="<?= htmlspecialchars($_SERVER["REQUEST_URI"], ENT_QUOTES) ?>" />
						<input type="image" class="pin-comment" src="/images/unpin.min.svg" width="11" height="11" alt="<?= __('Unpin comment') ?>" title="<?= __('Unpin comment') ?>" name="submit" value="1" />
					</fieldset>
				</form>
			<?php endif; ?>
		</h4>
		<div id="<?= $anchor ?>-content" class="article-content<?php if ($is_deleted): ?> comment-deleted<?php endif; ?>">
			<div>
				<?php if (!empty($row['RenderedComment'])): ?>
				<?= $row['RenderedComment'] ?>
				<?php else: ?>
				<p>
					<?= parse_comment($row['Comments']) ?>
				</p>
				<?php endif; ?>
			</div>
		</div>
	<?php endforeach; ?>
</div>

<script>
$(document).ready(function() {
	$('.edit-comment').click(function () {
		var parent_element = this.parentElement,
			parent_id = parent_element.id,
			comment_id = parent_id.substr(parent_id.indexOf('-') + 1),
			edit_form = $(parent_element).next(),
			_this = $(this);
		add_busy_indicator(_this);
		$.getJSON('<?= get_uri('/rpc') ?>', {
			type: 'get-comment-form',
			arg: comment_id,
			base_id: <?= intval($row["PackageBaseID"]) ?>,
			pkgbase_name: <?= json_encode($pkgbase_name) ?>
		}, function (data) {
			remove_busy_indicator(_this);
			if (data.success) {
				edit_form.html(data.form);
				edit_form.find('textarea').focus();
			} else {
				alert(data.error);
			}
		});
		return false;
	});

	function add_busy_indicator(sibling) {
		sibling.after('<img src="/images/ajax-loader.gif" class="ajax-loader" width="16" height="11" alt="Busy???" />');
	}

	function remove_busy_indicator(sibling) {
		sibling.next().remove();
	}
});
</script>
